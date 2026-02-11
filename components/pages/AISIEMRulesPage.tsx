'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { usePurpleTeamStore, DetectionRule } from '@/lib/store'
import toast from 'react-hot-toast'
import {
  ShieldExclamationIcon,
  CloudArrowUpIcon,
  SparklesIcon,
  DocumentDuplicateIcon,
  CheckIcon,
  CodeBracketIcon,
  AdjustmentsHorizontalIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
} from '@heroicons/react/24/outline'

export default function AISIEMRulesPage() {
  const {
    currentAnalysis,
    n8nConfig,
    updateRuleStatus,
    updateRuleEnrichment,
    setIsLoading,
    setLoadingMessage,
    addNotification,
  } = usePurpleTeamStore()

  const [expandedRule, setExpandedRule] = useState<string | null>(null)
  const [enrichingRule, setEnrichingRule] = useState<string | null>(null)

  const handleEnrichRule = async (rule: DetectionRule) => {
    if (!currentAnalysis) return

    setEnrichingRule(rule.id)
    setIsLoading(true)
    setLoadingMessage('Enriching rule with threat intelligence...')

    try {
      const webhookUrl = `${n8nConfig.base_url}${n8nConfig.webhook_threat_intel}`

      const payload = {
        execution_id: currentAnalysis.execution_id,
        rule_id: rule.id,
        rule_query: rule.query,
        mitre_techniques: rule.mitre,
        context: currentAnalysis.attack_summary.overview,
        timestamp: new Date().toISOString(),
      }

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })

      if (response.ok) {
        const result = await response.json()
        updateRuleEnrichment(
          currentAnalysis.execution_id,
          rule.id,
          result.enrichment || 'Threat intelligence enrichment applied'
        )
        toast.success('Rule enriched with threat intelligence')
      } else {
        throw new Error('Enrichment failed')
      }
    } catch (error) {
      toast.error('Failed to enrich rule')
    } finally {
      setEnrichingRule(null)
      setIsLoading(false)
      setLoadingMessage('')
    }
  }

  const handleApplyRule = async (rule: DetectionRule) => {
    if (!currentAnalysis) return

    setIsLoading(true)
    setLoadingMessage('Uploading rule to Elastic SIEM...')

    try {
      const webhookUrl = `${n8nConfig.base_url}${n8nConfig.webhook_elastic_rule}`

      // Format rule for Elastic Security
      const elasticRule = {
        name: rule.rule_name,
        description: `${rule.description}${rule.enrichment_data ? `\n\nThreat Intelligence:\n${rule.enrichment_data}` : ''}`,
        risk_score: rule.severity === 'critical' ? 99 : rule.severity === 'high' ? 73 : rule.severity === 'medium' ? 47 : 21,
        severity: rule.severity,
        type: rule.query.includes('sequence') ? 'eql' : 'query',
        query: rule.query,
        index: rule.index.split(',').map(i => i.trim()),
        threat: rule.mitre.map(technique => ({
          framework: 'MITRE ATT&CK',
          technique: {
            id: technique,
            name: technique,
          },
        })),
        tags: ['purple-team', 'automated', ...rule.mitre],
        enabled: true,
      }

      const payload = {
        execution_id: currentAnalysis.execution_id,
        rule_id: rule.id,
        elastic_url: n8nConfig.elastic_url,
        elastic_rule: elasticRule,
        timestamp: new Date().toISOString(),
      }

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })

      if (response.ok) {
        updateRuleStatus(currentAnalysis.execution_id, rule.id, 'applied')

        addNotification({
          id: `notif_${Date.now()}`,
          type: 'success',
          title: 'Rule Applied',
          message: `${rule.rule_name} uploaded to Elastic SIEM`,
          timestamp: new Date().toISOString(),
        })

        toast.success('Rule uploaded to Elastic SIEM')
      } else {
        throw new Error('Upload failed')
      }
    } catch (error) {
      toast.error('Failed to upload rule to Elastic')
    } finally {
      setIsLoading(false)
      setLoadingMessage('')
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-neon-red/20 text-neon-red border-neon-red/30'
      case 'high':
        return 'bg-neon-orange/20 text-neon-orange border-neon-orange/30'
      case 'medium':
        return 'bg-neon-yellow/20 text-neon-yellow border-neon-yellow/30'
      default:
        return 'bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30'
    }
  }

  const getStatusBadge = (status: DetectionRule['status']) => {
    switch (status) {
      case 'draft':
        return <span className="cyber-badge bg-slate/20 text-slate border-slate/30">DRAFT</span>
      case 'enriched':
        return <span className="cyber-badge-purple">ENRICHED</span>
      case 'applied':
        return <span className="cyber-badge-green">APPLIED</span>
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-wider text-white flex items-center gap-3">
            <ShieldExclamationIcon className="w-8 h-8 text-cyber-magenta" />
            SIEM DETECTION RULES
          </h1>
          <p className="text-slate mt-1">
            Review, enrich with threat intelligence, and deploy detection rules to Elastic SIEM
          </p>
        </div>
      </div>

      {currentAnalysis ? (
        <div className="space-y-4">
          {currentAnalysis.detection_rules.length === 0 ? (
            <div className="cyber-card rounded-2xl p-12 text-center">
              <ShieldExclamationIcon className="w-16 h-16 mx-auto mb-4 text-slate opacity-50" />
              <p className="text-slate">No detection rules generated</p>
            </div>
          ) : (
            currentAnalysis.detection_rules.map((rule, index) => (
              <motion.div
                key={rule.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="cyber-card rounded-2xl overflow-hidden"
              >
                {/* Rule Header */}
                <div
                  className="p-6 cursor-pointer"
                  onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-display text-lg font-semibold tracking-wider text-white">
                          {rule.rule_name}
                        </h3>
                        <span className={`cyber-badge ${getSeverityColor(rule.severity)}`}>
                          {rule.severity.toUpperCase()}
                        </span>
                        {getStatusBadge(rule.status)}
                      </div>
                      <p className="text-slate text-sm">{rule.description}</p>
                      <div className="flex flex-wrap gap-2 mt-3">
                        {rule.mitre.map((technique) => (
                          <span
                            key={technique}
                            className="px-2 py-1 bg-cyber-purple/20 text-cyber-purple text-xs rounded font-mono"
                          >
                            {technique}
                          </span>
                        ))}
                      </div>
                    </div>
                    <motion.div
                      animate={{ rotate: expandedRule === rule.id ? 180 : 0 }}
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
                  {expandedRule === rule.id && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                      className="border-t border-slate/20"
                    >
                      <div className="p-6 space-y-4">
                        {/* Query */}
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-display tracking-wider text-slate flex items-center gap-2">
                              <CodeBracketIcon className="w-4 h-4" />
                              QUERY ({rule.query.includes('sequence') ? 'EQL' : 'KQL'})
                            </span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation()
                                copyToClipboard(rule.query)
                              }}
                              className="flex items-center gap-1 text-xs text-cyber-purple hover:text-white transition-colors"
                            >
                              <DocumentDuplicateIcon className="w-4 h-4" />
                              Copy
                            </button>
                          </div>
                          <div className="code-block">
                            <code className="text-terminal text-sm whitespace-pre-wrap">{rule.query}</code>
                          </div>
                        </div>

                        {/* Index */}
                        <div>
                          <span className="text-xs font-display tracking-wider text-slate">INDEX PATTERN</span>
                          <p className="font-mono text-sm text-white mt-1">{rule.index}</p>
                        </div>

                        {/* False Positives */}
                        <div className="p-4 bg-neon-yellow/5 rounded-lg border border-neon-yellow/20">
                          <div className="flex items-center gap-2 mb-2">
                            <ExclamationTriangleIcon className="w-5 h-5 text-neon-yellow" />
                            <span className="text-xs font-display tracking-wider text-neon-yellow">
                              FALSE POSITIVES
                            </span>
                          </div>
                          <p className="text-slate text-sm">{rule.false_positives}</p>
                        </div>

                        {/* Tuning Notes */}
                        <div className="p-4 bg-cyber-cyan/5 rounded-lg border border-cyber-cyan/20">
                          <div className="flex items-center gap-2 mb-2">
                            <AdjustmentsHorizontalIcon className="w-5 h-5 text-cyber-cyan" />
                            <span className="text-xs font-display tracking-wider text-cyber-cyan">
                              TUNING RECOMMENDATIONS
                            </span>
                          </div>
                          <p className="text-slate text-sm">{rule.tuning_notes}</p>
                        </div>

                        {/* Enrichment Data */}
                        {rule.enrichment_data && (
                          <div className="p-4 bg-cyber-purple/5 rounded-lg border border-cyber-purple/20">
                            <div className="flex items-center gap-2 mb-2">
                              <SparklesIcon className="w-5 h-5 text-cyber-purple" />
                              <span className="text-xs font-display tracking-wider text-cyber-purple">
                                THREAT INTELLIGENCE ENRICHMENT
                              </span>
                            </div>
                            <p className="text-slate text-sm whitespace-pre-wrap">{rule.enrichment_data}</p>
                          </div>
                        )}

                        {/* Actions */}
                        <div className="flex gap-3 pt-4 border-t border-slate/20">
                          {rule.status !== 'applied' && (
                            <>
                              <motion.button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleEnrichRule(rule)
                                }}
                                disabled={enrichingRule === rule.id}
                                className="flex-1 cyber-btn-outline flex items-center justify-center gap-2"
                                whileHover={{ scale: 1.02 }}
                                whileTap={{ scale: 0.98 }}
                              >
                                <SparklesIcon className={`w-5 h-5 ${enrichingRule === rule.id ? 'animate-pulse' : ''}`} />
                                {enrichingRule === rule.id ? 'ENRICHING...' : 'ENRICH WITH TI'}
                              </motion.button>
                              <motion.button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleApplyRule(rule)
                                }}
                                className="flex-1 cyber-btn flex items-center justify-center gap-2"
                                whileHover={{ scale: 1.02 }}
                                whileTap={{ scale: 0.98 }}
                              >
                                <CloudArrowUpIcon className="w-5 h-5" />
                                APPLY TO ELASTIC
                              </motion.button>
                            </>
                          )}
                          {rule.status === 'applied' && (
                            <div className="flex-1 flex items-center justify-center gap-2 py-3 text-neon-green">
                              <CheckIcon className="w-5 h-5" />
                              <span className="font-display tracking-wider">Rule Applied to Elastic SIEM</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            ))
          )}
        </div>
      ) : (
        <div className="cyber-card rounded-2xl p-12 text-center">
          <ShieldExclamationIcon className="w-16 h-16 mx-auto mb-4 text-slate opacity-50" />
          <h2 className="font-display text-xl font-semibold tracking-wider text-white mb-2">
            No Analysis Selected
          </h2>
          <p className="text-slate">
            Select an analysis from the Ingest page to view detection rules
          </p>
        </div>
      )}
    </div>
  )
}

