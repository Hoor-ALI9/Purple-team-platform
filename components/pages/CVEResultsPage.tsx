'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { usePurpleTeamStore, ExternalCVEResult, CVEAnalysis } from '@/lib/store'
import toast from 'react-hot-toast'
import {
  BugAntIcon,
  ArrowPathIcon,
  DocumentDuplicateIcon,
  ShieldExclamationIcon,
  CodeBracketIcon,
  ExclamationTriangleIcon,
  TrashIcon,
  CloudArrowDownIcon,
  CommandLineIcon,
  ClockIcon,
  ArrowUpTrayIcon,
  DocumentTextIcon,
  ArrowDownTrayIcon,
} from '@heroicons/react/24/outline'

export default function CVEResultsPage() {
  const {
    externalCVEResults,
    addExternalCVEResult,
    clearExternalCVEResults,
    selectedExternalCVEResult,
    setSelectedExternalCVEResult,
  } = usePurpleTeamStore()

  const [isRefreshing, setIsRefreshing] = useState(false)
  const [expandedCVE, setExpandedCVE] = useState<string | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [isUploading, setIsUploading] = useState(false)

  // Parse CSV content to CVE results
  const parseCSV = (csvContent: string): CVEAnalysis[] => {
    const lines = csvContent.trim().split('\n')
    if (lines.length < 2) return []

    // Parse header to get column indices
    const header = lines[0].split(',')
    const getIndex = (name: string) => header.findIndex(h => 
      h.toLowerCase().trim().replace(/"/g, '').includes(name.toLowerCase())
    )

    const exploitIdx = getIndex('exploit_name')
    const cveIdx = getIndex('cve_id')
    const remediationIdx = getIndex('remediation')
    const sigmaIdx = getIndex('sigma')
    const mitigationIdx = getIndex('mitigation') !== -1 ? getIndex('mitigation') : getIndex('endpoint')

    const results: CVEAnalysis[] = []

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim()
      if (!line) continue

      // Handle CSV with quoted fields containing commas
      const values: string[] = []
      let current = ''
      let inQuotes = false
      
      for (let j = 0; j < line.length; j++) {
        const char = line[j]
        if (char === '"') {
          inQuotes = !inQuotes
        } else if (char === ',' && !inQuotes) {
          values.push(current.trim().replace(/^"|"$/g, ''))
          current = ''
        } else {
          current += char
        }
      }
      values.push(current.trim().replace(/^"|"$/g, ''))

      if (values.length >= 2) {
        results.push({
          exploit_name: values[exploitIdx] || values[0] || 'Unknown',
          cve_id: values[cveIdx] || values[1] || 'N/A',
          remediation_steps: values[remediationIdx] || values[2] || '',
          sigma_detection_queries: values[sigmaIdx] || values[3] || '',
          endpoint_mitigation_commands: values[mitigationIdx] || values[4] || '',
        })
      }
    }

    return results
  }

  // Handle CSV file upload
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    if (!file.name.toLowerCase().endsWith('.csv')) {
      toast.error('Please upload a CSV file')
      return
    }

    setIsUploading(true)
    try {
      const content = await file.text()
      const results = parseCSV(content)

      if (results.length === 0) {
        toast.error('No valid CVE data found in CSV')
        return
      }

      const newResult: ExternalCVEResult = {
        execution_id: `csv_upload_${Date.now()}`,
        source: 'csv_upload' as any,
        timestamp: new Date().toISOString(),
        results: results,
        metadata: {
          json_file: file.name,
        },
      }

      addExternalCVEResult(newResult)
      toast.success(`Loaded ${results.length} CVE result(s) from ${file.name}`)
    } catch (error) {
      console.error('Failed to parse CSV:', error)
      toast.error('Failed to parse CSV file')
    } finally {
      setIsUploading(false)
      // Reset file input
      event.target.value = ''
    }
  }

  const fetchResults = useCallback(async () => {
    setIsRefreshing(true)
    try {
      const response = await fetch('/api/webhook/cve-results?limit=20')
      if (response.ok) {
        const data = await response.json()
        if (data.success && data.data) {
          // Add new results that don't already exist
          const existingIds = new Set(externalCVEResults.map(r => r.execution_id))
          const newResults = data.data.filter((r: any) => !existingIds.has(r.execution_id))
          
          newResults.forEach((result: any) => {
            addExternalCVEResult({
              execution_id: result.execution_id,
              source: result.source || 'python_script',
              timestamp: result.timestamp,
              results: result.results || [],
              metadata: result.metadata,
            })
          })

          if (newResults.length > 0) {
            toast.success(`Loaded ${newResults.length} new CVE result(s)`)
          }
        }
      }
    } catch (error) {
      console.error('Failed to fetch CVE results:', error)
      toast.error('Failed to fetch CVE results')
    } finally {
      setIsRefreshing(false)
    }
  }, [externalCVEResults, addExternalCVEResult])

  // Auto-refresh every 10 seconds if enabled
  useEffect(() => {
    if (!autoRefresh) return
    const interval = setInterval(fetchResults, 10000)
    return () => clearInterval(interval)
  }, [autoRefresh, fetchResults])

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    toast.success(`${label} copied to clipboard`)
  }

  const downloadCsvForExecution = async (executionId: string) => {
    try {
      const url = `/api/webhook/cve-results?execution_id=${encodeURIComponent(executionId)}&format=csv`
      // Open in a new tab to trigger browser download behavior
      window.open(url, '_blank', 'noopener,noreferrer')
    } catch (error) {
      console.error('Failed to download CSV:', error)
      toast.error('Failed to download CSV')
    }
  }

  const copyCsvForExecution = async (executionId: string) => {
    try {
      const url = `/api/webhook/cve-results?execution_id=${encodeURIComponent(executionId)}&format=csv`
      const response = await fetch(url)
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      const csvText = await response.text()
      copyToClipboard(csvText, 'CSV')
    } catch (error) {
      console.error('Failed to copy CSV:', error)
      toast.error('Failed to copy CSV')
    }
  }

  const getSourceBadge = (source: string) => {
    switch (source) {
      case 'python_script':
        return (
          <span className="cyber-badge bg-cyber-purple/20 text-cyber-purple border-cyber-purple/30">
            <CommandLineIcon className="w-3 h-3 mr-1" />
            Python Script
          </span>
        )
      case 'discord_bot':
        return (
          <span className="cyber-badge bg-cyber-blue/20 text-cyber-blue border-cyber-blue/30">
            Discord Bot
          </span>
        )
      case 'csv_upload':
        return (
          <span className="cyber-badge bg-neon-green/20 text-neon-green border-neon-green/30">
            <DocumentTextIcon className="w-3 h-3 mr-1" />
            CSV Upload
          </span>
        )
      default:
        return (
          <span className="cyber-badge bg-slate/20 text-slate border-slate/30">
            {source}
          </span>
        )
    }
  }

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleString()
    } catch {
      return timestamp
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-wider text-white flex items-center gap-3">
            <BugAntIcon className="w-8 h-8 text-neon-red" />
            CVE RESULTS
          </h1>
          <p className="text-slate mt-1">
            View CVE analysis results from Python script and Discord bot
          </p>
        </div>
        <div className="flex gap-3">
          <label className="flex items-center gap-2 text-sm text-slate cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="w-4 h-4 rounded border-slate/30 bg-obsidian text-cyber-purple focus:ring-cyber-purple"
            />
            Auto-refresh
          </label>
          <motion.button
            onClick={fetchResults}
            disabled={isRefreshing}
            className="cyber-btn-outline flex items-center gap-2"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <ArrowPathIcon className={`w-5 h-5 ${isRefreshing ? 'animate-spin' : ''}`} />
            {isRefreshing ? 'REFRESHING...' : 'REFRESH'}
          </motion.button>
          {/* CSV Upload Button */}
          <label className="cyber-btn flex items-center gap-2 cursor-pointer">
            <ArrowUpTrayIcon className={`w-5 h-5 ${isUploading ? 'animate-pulse' : ''}`} />
            {isUploading ? 'UPLOADING...' : 'UPLOAD CSV'}
            <input
              type="file"
              accept=".csv"
              onChange={handleFileUpload}
              className="hidden"
              disabled={isUploading}
            />
          </label>
          {externalCVEResults.length > 0 && (
            <motion.button
              onClick={() => {
                clearExternalCVEResults()
                toast.success('Cleared all CVE results')
              }}
              className="cyber-btn-danger flex items-center gap-2"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <TrashIcon className="w-5 h-5" />
              CLEAR ALL
            </motion.button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Results List */}
        <div className="cyber-card rounded-2xl p-4">
          <h2 className="font-display text-sm font-semibold tracking-wider text-slate mb-4">
            RECEIVED RESULTS ({externalCVEResults.length})
          </h2>
          <div className="space-y-2 max-h-[600px] overflow-y-auto">
            {externalCVEResults.length === 0 ? (
              <div className="text-center py-8 text-slate">
                <CloudArrowDownIcon className="w-10 h-10 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No CVE results received</p>
                <p className="text-xs mt-1">Run the Python script or wait for Discord bot</p>
              </div>
            ) : (
              externalCVEResults.map((result) => (
                <button
                  key={result.execution_id}
                  onClick={() => setSelectedExternalCVEResult(result)}
                  className={`
                    w-full p-3 rounded-lg text-left transition-all duration-200
                    ${selectedExternalCVEResult?.execution_id === result.execution_id
                      ? 'bg-cyber-purple/20 border border-cyber-purple'
                      : 'bg-graphite/30 border border-transparent hover:bg-graphite/50'
                    }
                  `}
                >
                  <div className="flex items-center justify-between mb-1">
                    {getSourceBadge(result.source)}
                    <span className="text-xs text-slate">
                      {result.results.length} CVE(s)
                    </span>
                  </div>
                  <p className="font-mono text-xs text-white truncate">
                    {result.execution_id}
                  </p>
                  <div className="flex items-center gap-1 text-xs text-slate mt-1">
                    <ClockIcon className="w-3 h-3" />
                    {formatTimestamp(result.timestamp)}
                  </div>
                  {result.metadata?.json_file && (
                    <p className="text-xs text-cyber-cyan mt-1 truncate">
                      {result.metadata.json_file}
                    </p>
                  )}
                </button>
              ))
            )}
          </div>
        </div>

        {/* CVE Details */}
        <div className="lg:col-span-3 space-y-4">
          {selectedExternalCVEResult ? (
            <>
              {/* Summary Header */}
              <div className="cyber-card rounded-2xl p-6">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-3 mb-2">
                      <h2 className="font-display text-xl font-semibold tracking-wider text-white">
                        CVE Analysis Results
                      </h2>
                      {getSourceBadge(selectedExternalCVEResult.source)}
                    </div>
                    <p className="font-mono text-sm text-slate">
                      {selectedExternalCVEResult.execution_id}
                    </p>
                    <p className="text-sm text-slate mt-1">
                      Received: {formatTimestamp(selectedExternalCVEResult.timestamp)}
                    </p>
                    {selectedExternalCVEResult.metadata?.json_file && (
                      <p className="text-sm text-cyber-cyan mt-1">
                        Source: {selectedExternalCVEResult.metadata.json_file}
                      </p>
                    )}
                  </div>
                  <div className="text-right">
                    <div className="text-3xl font-bold text-neon-red">
                      {selectedExternalCVEResult.results.length}
                    </div>
                    <div className="text-xs text-slate">CVE(s) Analyzed</div>
                    <div className="flex items-center justify-end gap-2 mt-3">
                      <motion.button
                        onClick={() => downloadCsvForExecution(selectedExternalCVEResult.execution_id)}
                        className="cyber-btn-outline flex items-center gap-2 text-xs"
                        whileHover={{ scale: 1.03 }}
                        whileTap={{ scale: 0.97 }}
                      >
                        <ArrowDownTrayIcon className="w-4 h-4" />
                        DOWNLOAD CSV
                      </motion.button>
                      <motion.button
                        onClick={() => copyCsvForExecution(selectedExternalCVEResult.execution_id)}
                        className="cyber-btn-outline flex items-center gap-2 text-xs"
                        whileHover={{ scale: 1.03 }}
                        whileTap={{ scale: 0.97 }}
                      >
                        <DocumentDuplicateIcon className="w-4 h-4" />
                        COPY CSV
                      </motion.button>
                    </div>
                  </div>
                </div>
              </div>

              {/* CVE Cards */}
              <AnimatePresence mode="wait">
                {selectedExternalCVEResult.results.map((cve, index) => (
                  <motion.div
                    key={`${selectedExternalCVEResult.execution_id}-${index}`}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ delay: index * 0.1 }}
                    className="cyber-card rounded-2xl overflow-hidden"
                  >
                    {/* CVE Header */}
                    <div
                      className="p-6 cursor-pointer"
                      onClick={() => setExpandedCVE(
                        expandedCVE === `${selectedExternalCVEResult.execution_id}-${index}`
                          ? null
                          : `${selectedExternalCVEResult.execution_id}-${index}`
                      )}
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <h3 className="font-display text-lg font-semibold tracking-wider text-white mb-1">
                            {cve.exploit_name}
                          </h3>
                          <p className="font-mono text-sm text-neon-red">{cve.cve_id}</p>
                        </div>
                        <motion.div
                          animate={{
                            rotate: expandedCVE === `${selectedExternalCVEResult.execution_id}-${index}` ? 180 : 0
                          }}
                          transition={{ duration: 0.2 }}
                        >
                          <svg className="w-6 h-6 text-slate" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </motion.div>
                      </div>
                    </div>

                    {/* Expanded Content */}
                    <AnimatePresence>
                      {expandedCVE === `${selectedExternalCVEResult.execution_id}-${index}` && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.2 }}
                          className="border-t border-slate/20"
                        >
                          <div className="p-6 space-y-6">
                            {/* Remediation Steps */}
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-2">
                                  <ShieldExclamationIcon className="w-5 h-5 text-neon-green" />
                                  <span className="text-xs font-display tracking-wider text-slate">
                                    REMEDIATION STEPS
                                  </span>
                                </div>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    copyToClipboard(cve.remediation_steps, 'Remediation steps')
                                  }}
                                  className="flex items-center gap-1 text-xs text-cyber-purple hover:text-white transition-colors"
                                >
                                  <DocumentDuplicateIcon className="w-4 h-4" />
                                  Copy
                                </button>
                              </div>
                              <div className="code-block max-h-64 overflow-y-auto">
                                <code className="text-terminal text-sm whitespace-pre-wrap">
                                  {cve.remediation_steps}
                                </code>
                              </div>
                            </div>

                            {/* SIGMA Detection Queries */}
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-2">
                                  <CodeBracketIcon className="w-5 h-5 text-cyber-cyan" />
                                  <span className="text-xs font-display tracking-wider text-slate">
                                    SIGMA RULES & QUERIES
                                  </span>
                                </div>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    copyToClipboard(cve.sigma_detection_queries, 'SIGMA rules')
                                  }}
                                  className="flex items-center gap-1 text-xs text-cyber-purple hover:text-white transition-colors"
                                >
                                  <DocumentDuplicateIcon className="w-4 h-4" />
                                  Copy
                                </button>
                              </div>
                              <div className="code-block max-h-64 overflow-y-auto">
                                <code className="text-terminal text-sm whitespace-pre-wrap">
                                  {cve.sigma_detection_queries}
                                </code>
                              </div>
                            </div>

                            {/* Endpoint Mitigation Commands */}
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-2">
                                  <ExclamationTriangleIcon className="w-5 h-5 text-neon-yellow" />
                                  <span className="text-xs font-display tracking-wider text-slate">
                                    ENDPOINT MITIGATION COMMANDS
                                  </span>
                                </div>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    copyToClipboard(cve.endpoint_mitigation_commands, 'Mitigation commands')
                                  }}
                                  className="flex items-center gap-1 text-xs text-cyber-purple hover:text-white transition-colors"
                                >
                                  <DocumentDuplicateIcon className="w-4 h-4" />
                                  Copy
                                </button>
                              </div>
                              <div className="code-block max-h-64 overflow-y-auto">
                                <code className="text-terminal text-sm whitespace-pre-wrap">
                                  {cve.endpoint_mitigation_commands}
                                </code>
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                ))}
              </AnimatePresence>
            </>
          ) : (
            <div className="cyber-card rounded-2xl p-12 text-center">
              <BugAntIcon className="w-16 h-16 mx-auto mb-4 text-slate opacity-50" />
              <h2 className="font-display text-xl font-semibold tracking-wider text-white mb-2">
                No Result Selected
              </h2>
              <p className="text-slate mb-4">
                Select a result from the list or refresh to fetch new results
              </p>
              <motion.button
                onClick={fetchResults}
                className="cyber-btn flex items-center gap-2 mx-auto"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <ArrowPathIcon className="w-5 h-5" />
                FETCH RESULTS
              </motion.button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
