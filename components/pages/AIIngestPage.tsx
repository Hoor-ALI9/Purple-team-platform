'use client'

import { useState, useRef } from 'react'
import { motion } from 'framer-motion'
import { usePurpleTeamStore, AIAnalysis } from '@/lib/store'
import toast from 'react-hot-toast'
import {
  DocumentMagnifyingGlassIcon,
  ArrowDownTrayIcon,
  ChartBarIcon,
  ClockIcon,
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  CheckBadgeIcon,
  DocumentTextIcon,
  BugAntIcon,
  CodeBracketIcon,
  DocumentDuplicateIcon,
  Cog6ToothIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline'

export default function AIIngestPage() {
  const { 
    currentAnalysis, 
    analyses, 
    setCurrentAnalysis, 
    attackResults, 
    currentAttack,
    updateCVEAnalysis,
    setIsLoading,
    setLoadingMessage,
    addNotification,
    aiPromptSettings,
    updateAIPromptSettings,
    resetAIPromptSettings,
    attackVectors,
  } = usePurpleTeamStore()
  const [selectedAnalysis, setSelectedAnalysis] = useState<AIAnalysis | null>(currentAnalysis)
  const [showSettings, setShowSettings] = useState(false)
  const [tempPromptSettings, setTempPromptSettings] = useState(aiPromptSettings)
  const reportRef = useRef<HTMLDivElement>(null)

  const handleAnalysisSelect = (analysis: AIAnalysis) => {
    setSelectedAnalysis(analysis)
    setCurrentAnalysis(analysis)
  }

  const handleCVEAnalysis = async () => {
    if (!selectedAnalysis) {
      toast.error('No analysis selected')
      return
    }

    setIsLoading(true)
    setLoadingMessage('Analyzing exploits and mapping to CVEs...')

    try {
      // Collect all attack data directly - pass everything and let API extract exploit names
      const relevantAttackResults = attackResults.filter(
        r => r.execution_id === selectedAnalysis.execution_id && r.success
      )

      // Get relevant attack vectors for this execution
      const relevantAttackVectors = attackVectors.filter(
        v => v.status === 'completed' || v.status === 'running'
      )

      // Build complete exploit data from all available sources
      const exploitData: any = {
        execution_id: selectedAnalysis.execution_id,
        success: true,
        // Include the full analysis object
        analysis: selectedAnalysis,
        // Include all relevant attack results with their raw_output
        attack_results: relevantAttackResults.map(r => ({
          execution_id: r.execution_id,
          attack_type: r.attack_type,
          target_ip: r.target_ip,
          target_port: r.target_port,
          raw_output: r.raw_output,
          success: r.success,
          os_type: r.os_type,
        })),
        // Include current attack if it matches
        ...(currentAttack && currentAttack.execution_id === selectedAnalysis.execution_id && {
          current_attack: {
            execution_id: currentAttack.execution_id,
            attack_type: currentAttack.attack_type,
            target_ip: currentAttack.target_ip,
            target_port: currentAttack.target_port,
            raw_output: currentAttack.raw_output,
            success: currentAttack.success,
            os_type: currentAttack.os_type,
          },
        }),
        // Include attack vectors with kill chain data
        ...(relevantAttackVectors.length > 0 && {
          attackVectors: relevantAttackVectors.map(v => ({
            id: v.id,
            name: v.name,
            status: v.status,
            killChain: v.killChain,
            executionResults: v.executionResults,
          })),
        }),
      }

      const response = await fetch('/api/ai-analysis/cve-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          exploit_data: exploitData,
          execution_id: selectedAnalysis.execution_id,
          ai_prompt_settings: aiPromptSettings,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }))
        throw new Error(errorData.error || 'CVE analysis failed')
      }

      const result = await response.json()
      
      if (result.success && result.results) {
        updateCVEAnalysis(selectedAnalysis.execution_id, result.results)
        
        addNotification({
          id: `notif_${Date.now()}`,
          type: 'success',
          title: 'CVE Analysis Complete',
          message: `Mapped ${result.results.length} exploit(s) to CVE(s)`,
          timestamp: new Date().toISOString(),
        })

        toast.success(`CVE analysis complete: ${result.results.length} exploit(s) analyzed`)
      } else {
        throw new Error(result.error || 'Unknown error')
      }
    } catch (error: any) {
      console.error('CVE analysis error:', error)
      toast.error(error.message || 'Failed to perform CVE analysis')
    } finally {
      setIsLoading(false)
      setLoadingMessage('')
    }
  }

  const generatePDFReport = async () => {
    if (!selectedAnalysis) {
      toast.error('No analysis selected')
      return
    }

    try {
      // Dynamic import jsPDF
      const jsPDFModule = await import('jspdf')
      const jsPDF = jsPDFModule.default
      const autoTableModule = await import('jspdf-autotable')
      
      const doc = new jsPDF()
      const pageWidth = doc.internal.pageSize.getWidth()
      const pageHeight = doc.internal.pageSize.getHeight()
      
      // Header
      doc.setFillColor(18, 18, 26)
      doc.rect(0, 0, pageWidth, 45, 'F')
      
      doc.setTextColor(168, 85, 247)
      doc.setFontSize(24)
      doc.setFont('helvetica', 'bold')
      doc.text('PURPLE TEAM OPS', 20, 20)
      
      doc.setTextColor(255, 255, 255)
      doc.setFontSize(12)
      doc.text('Security Analysis Report', 20, 30)
      
      doc.setTextColor(100, 100, 120)
      doc.setFontSize(10)
      doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 38)
      doc.text(`Execution ID: ${selectedAnalysis.execution_id}`, pageWidth - 80, 38)

      let yPos = 55

      // Executive Summary
      doc.setTextColor(168, 85, 247)
      doc.setFontSize(14)
      doc.setFont('helvetica', 'bold')
      doc.text('EXECUTIVE SUMMARY', 20, yPos)
      yPos += 10

      doc.setTextColor(60, 60, 80)
      doc.setFontSize(10)
      doc.setFont('helvetica', 'normal')
      
      const summaryLines = doc.splitTextToSize(selectedAnalysis.attack_summary.overview, pageWidth - 40)
      doc.text(summaryLines, 20, yPos)
      yPos += summaryLines.length * 5 + 10

      // Key Metrics Box
      doc.setFillColor(26, 26, 36)
      doc.roundedRect(20, yPos, pageWidth - 40, 25, 3, 3, 'F')
      
      doc.setTextColor(168, 85, 247)
      doc.setFontSize(9)
      doc.text('ATTACKER OBJECTIVE', 30, yPos + 8)
      doc.text('SKILL LEVEL', 90, yPos + 8)
      doc.text('CONFIDENCE', 140, yPos + 8)
      
      doc.setTextColor(255, 255, 255)
      doc.setFontSize(10)
      doc.text(selectedAnalysis.attack_summary.attacker_objective, 30, yPos + 18)
      doc.text(selectedAnalysis.attack_summary.skill_level, 90, yPos + 18)
      doc.text(`${selectedAnalysis.attack_summary.confidence}%`, 140, yPos + 18)
      
      yPos += 35

      // Attack Timeline
      doc.setTextColor(168, 85, 247)
      doc.setFontSize(14)
      doc.setFont('helvetica', 'bold')
      doc.text('ATTACK TIMELINE', 20, yPos)
      yPos += 8

      if (selectedAnalysis.attack_timeline.length > 0) {
        const timelineData = selectedAnalysis.attack_timeline.map(event => [
          event.timestamp,
          event.action.substring(0, 30),
          event.mitre.join(', '),
          event.risk
        ])

        ;(doc as any).autoTable({
          startY: yPos,
          head: [['Timestamp', 'Action', 'MITRE', 'Risk']],
          body: timelineData,
          theme: 'grid',
          headStyles: { fillColor: [168, 85, 247], textColor: 255 },
          bodyStyles: { textColor: [60, 60, 80] },
          alternateRowStyles: { fillColor: [245, 245, 250] },
          margin: { left: 20, right: 20 },
        })

        yPos = (doc as any).lastAutoTable.finalY + 15
      }

      // Check if we need a new page
      if (yPos > pageHeight - 60) {
        doc.addPage()
        yPos = 20
      }

      // Impact Assessment
      doc.setTextColor(168, 85, 247)
      doc.setFontSize(14)
      doc.setFont('helvetica', 'bold')
      doc.text('IMPACT ASSESSMENT', 20, yPos)
      yPos += 10

      doc.setTextColor(60, 60, 80)
      doc.setFontSize(10)
      doc.setFont('helvetica', 'normal')
      
      doc.text(`Blast Radius: ${selectedAnalysis.impact_assessment.blast_radius}`, 20, yPos)
      yPos += 6
      doc.text(`Business Risk: ${selectedAnalysis.impact_assessment.business_risk}`, 20, yPos)
      yPos += 6
      
      const worstCaseLines = doc.splitTextToSize(
        `Worst Case: ${selectedAnalysis.impact_assessment.worst_case_scenario}`,
        pageWidth - 40
      )
      doc.text(worstCaseLines, 20, yPos)
      yPos += worstCaseLines.length * 5 + 10

      // Check if we need a new page
      if (yPos > pageHeight - 80) {
        doc.addPage()
        yPos = 20
      }

      // Detection Rules
      doc.setTextColor(168, 85, 247)
      doc.setFontSize(14)
      doc.setFont('helvetica', 'bold')
      doc.text('DETECTION RULES', 20, yPos)
      yPos += 8

      if (selectedAnalysis.detection_rules.length > 0) {
        const rulesData = selectedAnalysis.detection_rules.map(rule => [
          rule.rule_name.substring(0, 25),
          rule.severity.toUpperCase(),
          rule.mitre.join(', '),
          rule.status
        ])

        ;(doc as any).autoTable({
          startY: yPos,
          head: [['Rule Name', 'Severity', 'MITRE', 'Status']],
          body: rulesData,
          theme: 'grid',
          headStyles: { fillColor: [168, 85, 247], textColor: 255 },
          bodyStyles: { textColor: [60, 60, 80] },
          alternateRowStyles: { fillColor: [245, 245, 250] },
          margin: { left: 20, right: 20 },
        })
      }

      // Footer on all pages
      const pageCount = doc.getNumberOfPages()
      for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i)
        doc.setFillColor(18, 18, 26)
        doc.rect(0, pageHeight - 15, pageWidth, 15, 'F')
        doc.setTextColor(100, 100, 120)
        doc.setFontSize(8)
        doc.text('CONFIDENTIAL - Purple Team Operations', 20, pageHeight - 6)
        doc.text(`Page ${i} of ${pageCount}`, pageWidth - 30, pageHeight - 6)
      }

      // Save the PDF
      doc.save(`purple-team-report-${selectedAnalysis.execution_id}.pdf`)
      toast.success('Report exported successfully')
    } catch (error) {
      console.error('PDF generation error:', error)
      toast.error('Failed to generate PDF')
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-neon-red'
      case 'high': return 'text-neon-orange'
      case 'medium': return 'text-neon-yellow'
      default: return 'text-cyber-cyan'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-wider text-white flex items-center gap-3">
            <DocumentMagnifyingGlassIcon className="w-8 h-8 text-cyber-cyan" />
            AI INGEST & REPORT
          </h1>
          <p className="text-slate mt-1">
            View AI-generated analysis of attack executions and export professional reports
          </p>
        </div>
        <div className="flex gap-3">
          <motion.button
            onClick={() => {
              setTempPromptSettings(aiPromptSettings)
              setShowSettings(true)
            }}
            className="cyber-btn-outline flex items-center gap-2"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Cog6ToothIcon className="w-5 h-5" />
            SETTINGS
          </motion.button>
          {selectedAnalysis && (
            <>
              <motion.button
                onClick={handleCVEAnalysis}
                className="cyber-btn-outline flex items-center gap-2"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                disabled={selectedAnalysis.cve_analysis !== undefined}
              >
                <BugAntIcon className="w-5 h-5" />
                {selectedAnalysis.cve_analysis ? 'CVE ANALYZED' : 'ANALYZE CVE'}
              </motion.button>
              <motion.button
                onClick={generatePDFReport}
                className="cyber-btn flex items-center gap-2"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <ArrowDownTrayIcon className="w-5 h-5" />
                EXPORT PDF
              </motion.button>
            </>
          )}
        </div>
      </div>

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="cyber-card rounded-2xl p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto"
          >
            <div className="flex items-center justify-between mb-6">
              <h2 className="font-display text-2xl font-bold tracking-wider text-white flex items-center gap-2">
                <Cog6ToothIcon className="w-6 h-6 text-cyber-cyan" />
                AI PROMPT SETTINGS
              </h2>
              <button
                onClick={() => setShowSettings(false)}
                className="text-slate hover:text-white transition-colors"
              >
                <XMarkIcon className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-6">
              <div>
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  Map Exploit to CVE Prompt
                </label>
                <textarea
                  value={tempPromptSettings.mapExploitToCVE}
                  onChange={(e) => setTempPromptSettings({ ...tempPromptSettings, mapExploitToCVE: e.target.value })}
                  className="w-full h-32 px-4 py-3 bg-obsidian border border-slate/20 rounded-lg text-white font-mono text-sm focus:border-cyber-purple focus:outline-none"
                  placeholder="Use {exploit_name} as placeholder"
                />
              </div>

              <div>
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  Get Remediation Steps Prompt
                </label>
                <textarea
                  value={tempPromptSettings.getRemediationSteps}
                  onChange={(e) => setTempPromptSettings({ ...tempPromptSettings, getRemediationSteps: e.target.value })}
                  className="w-full h-32 px-4 py-3 bg-obsidian border border-slate/20 rounded-lg text-white font-mono text-sm focus:border-cyber-purple focus:outline-none"
                  placeholder="Use {cve_id} as placeholder"
                />
              </div>

              <div>
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  Get SIGMA Rules & Queries Prompt
                </label>
                <textarea
                  value={tempPromptSettings.getSigmaAndQueries}
                  onChange={(e) => setTempPromptSettings({ ...tempPromptSettings, getSigmaAndQueries: e.target.value })}
                  className="w-full h-32 px-4 py-3 bg-obsidian border border-slate/20 rounded-lg text-white font-mono text-sm focus:border-cyber-purple focus:outline-none"
                  placeholder="Use {cve_id} as placeholder"
                />
              </div>

              <div>
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  Get Endpoint Mitigation Commands Prompt
                </label>
                <textarea
                  value={tempPromptSettings.getEndpointMitigationCommands}
                  onChange={(e) => setTempPromptSettings({ ...tempPromptSettings, getEndpointMitigationCommands: e.target.value })}
                  className="w-full h-32 px-4 py-3 bg-obsidian border border-slate/20 rounded-lg text-white font-mono text-sm focus:border-cyber-purple focus:outline-none"
                  placeholder="Use {cve_id} as placeholder"
                />
              </div>

              <div>
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  Get What Actually Happened Prompt
                </label>
                <textarea
                  value={tempPromptSettings.getWhatActuallyHappened}
                  onChange={(e) => setTempPromptSettings({ ...tempPromptSettings, getWhatActuallyHappened: e.target.value })}
                  className="w-full h-40 px-4 py-3 bg-obsidian border border-slate/20 rounded-lg text-white font-mono text-sm focus:border-cyber-purple focus:outline-none"
                  placeholder="Use {attack_results} and {exploit_name} as placeholders"
                />
              </div>

              <div className="flex gap-3 justify-end">
                <motion.button
                  onClick={() => {
                    resetAIPromptSettings()
                    setTempPromptSettings(aiPromptSettings)
                    toast.success('Prompts reset to defaults')
                  }}
                  className="cyber-btn-outline"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  RESET DEFAULTS
                </motion.button>
                <motion.button
                  onClick={() => {
                    updateAIPromptSettings(tempPromptSettings)
                    setShowSettings(false)
                    toast.success('Settings saved')
                  }}
                  className="cyber-btn"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  SAVE SETTINGS
                </motion.button>
              </div>
            </div>
          </motion.div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Analysis List */}
        <div className="cyber-card rounded-2xl p-4">
          <h2 className="font-display text-sm font-semibold tracking-wider text-slate mb-4">
            AVAILABLE ANALYSES
          </h2>
          <div className="space-y-2 max-h-[600px] overflow-y-auto">
            {analyses.length === 0 ? (
              <div className="text-center py-8 text-slate">
                <DocumentTextIcon className="w-10 h-10 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No analyses available</p>
                <p className="text-xs mt-1">Execute an attack to generate analysis</p>
              </div>
            ) : (
              analyses.map((analysis) => (
                <button
                  key={analysis.execution_id}
                  onClick={() => handleAnalysisSelect(analysis)}
                  className={`
                    w-full p-3 rounded-lg text-left transition-all duration-200
                    ${selectedAnalysis?.execution_id === analysis.execution_id
                      ? 'bg-cyber-purple/20 border border-cyber-purple'
                      : 'bg-graphite/30 border border-transparent hover:bg-graphite/50'
                    }
                  `}
                >
                  <p className="font-mono text-xs text-white truncate">
                    {analysis.execution_id}
                  </p>
                  <p className="text-xs text-slate mt-1">
                    Confidence: {analysis.overall_confidence}%
                  </p>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Analysis Content */}
        <div className="lg:col-span-3 space-y-6">
          {selectedAnalysis ? (
            <>
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="cyber-card rounded-xl p-4"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <ShieldExclamationIcon className="w-5 h-5 text-cyber-purple" />
                    <span className="text-xs font-display tracking-wider text-slate">OBJECTIVE</span>
                  </div>
                  <p className="text-lg font-semibold text-white">
                    {selectedAnalysis.attack_summary.attacker_objective}
                  </p>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 }}
                  className="cyber-card rounded-xl p-4"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <ChartBarIcon className="w-5 h-5 text-neon-orange" />
                    <span className="text-xs font-display tracking-wider text-slate">SKILL LEVEL</span>
                  </div>
                  <p className="text-lg font-semibold text-white">
                    {selectedAnalysis.attack_summary.skill_level}
                  </p>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                  className="cyber-card rounded-xl p-4"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <CheckBadgeIcon className="w-5 h-5 text-neon-green" />
                    <span className="text-xs font-display tracking-wider text-slate">CONFIDENCE</span>
                  </div>
                  <p className="text-lg font-semibold text-white">
                    {selectedAnalysis.overall_confidence}%
                  </p>
                </motion.div>
              </div>

              {/* Overview */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="cyber-card rounded-2xl p-6"
                ref={reportRef}
              >
                <h2 className="font-display text-lg font-semibold tracking-wider text-white mb-4">
                  ATTACK OVERVIEW
                </h2>
                <p className="text-slate leading-relaxed">
                  {selectedAnalysis.attack_summary.overview}
                </p>
              </motion.div>

              {/* Timeline */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="cyber-card rounded-2xl p-6"
              >
                <h2 className="font-display text-lg font-semibold tracking-wider text-white mb-4 flex items-center gap-2">
                  <ClockIcon className="w-5 h-5 text-cyber-cyan" />
                  ATTACK TIMELINE
                </h2>
                <div className="space-y-4">
                  {selectedAnalysis.attack_timeline.map((event, index) => (
                    <div
                      key={index}
                      className="flex gap-4 p-4 bg-graphite/30 rounded-xl border-l-4 border-cyber-purple"
                    >
                      <div className="flex-shrink-0 w-24">
                        <span className="font-mono text-xs text-slate">{event.timestamp}</span>
                      </div>
                      <div className="flex-1">
                        <p className="font-semibold text-white mb-1">{event.action}</p>
                        <p className="text-sm text-slate mb-2">{event.intent}</p>
                        <div className="flex flex-wrap gap-2">
                          {event.mitre.map((technique) => (
                            <span
                              key={technique}
                              className="px-2 py-1 bg-cyber-purple/20 text-cyber-purple text-xs rounded font-mono"
                            >
                              {technique}
                            </span>
                          ))}
                          <span className={`px-2 py-1 text-xs rounded font-mono ${
                            event.risk === 'critical' ? 'bg-neon-red/20 text-neon-red' :
                            event.risk === 'high' ? 'bg-neon-orange/20 text-neon-orange' :
                            'bg-neon-yellow/20 text-neon-yellow'
                          }`}>
                            {event.risk.toUpperCase()}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>

              {/* Impact Assessment */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 }}
                className="cyber-card rounded-2xl p-6"
              >
                <h2 className="font-display text-lg font-semibold tracking-wider text-white mb-4 flex items-center gap-2">
                  <ExclamationTriangleIcon className="w-5 h-5 text-neon-red" />
                  IMPACT ASSESSMENT
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="text-sm font-display tracking-wider text-slate mb-2">BLAST RADIUS</h3>
                    <p className="text-white">{selectedAnalysis.impact_assessment.blast_radius}</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-display tracking-wider text-slate mb-2">BUSINESS RISK</h3>
                    <p className="text-white">{selectedAnalysis.impact_assessment.business_risk}</p>
                  </div>
                  <div className="md:col-span-2">
                    <h3 className="text-sm font-display tracking-wider text-slate mb-2">WORST CASE SCENARIO</h3>
                    <p className="text-neon-red">{selectedAnalysis.impact_assessment.worst_case_scenario}</p>
                  </div>
                  <div className="md:col-span-2">
                    <h3 className="text-sm font-display tracking-wider text-slate mb-2">AFFECTED ASSETS</h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedAnalysis.impact_assessment.assets_affected.map((asset, i) => (
                        <span key={i} className="px-3 py-1 bg-neon-red/10 text-neon-red text-sm rounded-lg border border-neon-red/30">
                          {asset}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </motion.div>

              {/* Assumptions & Gaps */}
              {selectedAnalysis.assumptions_and_gaps.length > 0 && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.6 }}
                  className="cyber-card rounded-2xl p-6"
                >
                  <h2 className="font-display text-lg font-semibold tracking-wider text-white mb-4">
                    ASSUMPTIONS & TELEMETRY GAPS
                  </h2>
                  <ul className="space-y-2">
                    {selectedAnalysis.assumptions_and_gaps.map((gap, i) => (
                      <li key={i} className="flex items-start gap-2 text-slate">
                        <span className="text-cyber-purple">•</span>
                        {gap}
                      </li>
                    ))}
                  </ul>
                </motion.div>
              )}

              {/* CVE Analysis */}
              {selectedAnalysis.cve_analysis && selectedAnalysis.cve_analysis.length > 0 && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.7 }}
                  className="cyber-card rounded-2xl p-6"
                >
                  <h2 className="font-display text-lg font-semibold tracking-wider text-white mb-4 flex items-center gap-2">
                    <BugAntIcon className="w-5 h-5 text-neon-red" />
                    CVE ANALYSIS & REMEDIATION
                  </h2>
                  <div className="space-y-6">
                    {selectedAnalysis.cve_analysis.map((cve, index) => (
                      <div
                        key={index}
                        className="p-4 bg-graphite/30 rounded-xl border-l-4 border-neon-red"
                      >
                        <div className="flex items-start justify-between mb-4">
                          <div>
                            <h3 className="font-display text-base font-semibold tracking-wider text-white mb-1">
                              {cve.exploit_name}
                            </h3>
                            <p className="font-mono text-sm text-neon-red">{cve.cve_id}</p>
                          </div>
                        </div>

                        {/* What Actually Happened */}
                        {cve.what_actually_happened && (
                          <div className="mb-4">
                            <div className="flex items-center gap-2 mb-2">
                              <DocumentTextIcon className="w-4 h-4 text-cyber-cyan" />
                              <span className="text-xs font-display tracking-wider text-slate">WHAT ACTUALLY HAPPENED</span>
                            </div>
                            <div className="code-block">
                              <code className="text-terminal text-sm whitespace-pre-wrap">{cve.what_actually_happened}</code>
                            </div>
                          </div>
                        )}

                        {/* Remediation Steps */}
                        <div className="mb-4">
                          <div className="flex items-center gap-2 mb-2">
                            <ShieldExclamationIcon className="w-4 h-4 text-neon-green" />
                            <span className="text-xs font-display tracking-wider text-slate">REMEDIATION STEPS</span>
                          </div>
                          <div className="code-block">
                            <code className="text-terminal text-sm whitespace-pre-wrap">{cve.remediation_steps}</code>
                          </div>
                        </div>

                        {/* SIGMA Detection Queries */}
                        <div className="mb-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <CodeBracketIcon className="w-4 h-4 text-cyber-cyan" />
                              <span className="text-xs font-display tracking-wider text-slate">SIGMA RULES & QUERIES</span>
                            </div>
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(cve.sigma_detection_queries)
                                toast.success('Copied to clipboard')
                              }}
                              className="flex items-center gap-1 text-xs text-cyber-purple hover:text-white transition-colors"
                            >
                              <DocumentDuplicateIcon className="w-4 h-4" />
                              Copy
                            </button>
                          </div>
                          <div className="code-block">
                            <code className="text-terminal text-sm whitespace-pre-wrap">{cve.sigma_detection_queries}</code>
                          </div>
                        </div>

                        {/* Endpoint Mitigation Commands */}
                        <div>
                          <div className="flex items-center gap-2 mb-2">
                            <ExclamationTriangleIcon className="w-4 h-4 text-neon-yellow" />
                            <span className="text-xs font-display tracking-wider text-slate">ENDPOINT MITIGATION COMMANDS</span>
                          </div>
                          <div className="code-block">
                            <code className="text-terminal text-sm whitespace-pre-wrap">{cve.endpoint_mitigation_commands}</code>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </>
          ) : (
            <div className="cyber-card rounded-2xl p-12 text-center">
              <DocumentMagnifyingGlassIcon className="w-16 h-16 mx-auto mb-4 text-slate opacity-50" />
              <h2 className="font-display text-xl font-semibold tracking-wider text-white mb-2">
                No Analysis Selected
              </h2>
              <p className="text-slate">
                Select an analysis from the list or execute an attack to generate a new analysis
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

