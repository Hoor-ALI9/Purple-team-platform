'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { usePurpleTeamStore, DetectionRule } from '@/lib/store'
import toast from 'react-hot-toast'
import {
  ShieldExclamationIcon,
  CloudArrowUpIcon,
  SparklesIcon,
  DocumentDuplicateIcon,
} from '@heroicons/react/24/outline'

export default function AISIEMRulesPage() {
  const {
    currentAnalysis,
    n8nConfig,
    setIsLoading,
    setLoadingMessage,
    addNotification,
  } = usePurpleTeamStore()

  const [enriching, setEnriching] = useState(false)
  const [enrichment, setEnrichment] = useState('')
  const [applied, setApplied] = useState(false)

  const [ruleName, setRuleName] = useState('')
  const [description, setDescription] = useState('')
  const [index, setIndex] = useState('logs-*, winlogbeat-*')
  const [severity, setSeverity] = useState<DetectionRule['severity']>('medium')
  const [mitreInput, setMitreInput] = useState('')
  const [query, setQuery] = useState('')

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  }

  const buildRule = (): DetectionRule => {
    const mitre = mitreInput
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean)

    return {
      id: `manual_${Date.now()}`,
      rule_name: ruleName.trim() || 'Manual Rule',
      description: description.trim() || 'Manual SIEM rule',
      index: index.trim() || 'logs-*',
      query: query,
      severity,
      mitre,
      false_positives: '',
      tuning_notes: '',
      status: applied ? 'applied' : enrichment ? 'enriched' : 'draft',
      enrichment_data: enrichment || undefined,
    }
  }

  const handleEnrichRule = async () => {
    if (!currentAnalysis) return
    if (!query.trim()) {
      toast.error('Rule query is required')
      return
    }

    const rule = buildRule()
    setEnriching(true)
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
        setEnrichment(result.enrichment || 'Threat intelligence enrichment applied')
        setApplied(false)
        toast.success('Rule enriched with threat intelligence')
      } else {
        throw new Error('Enrichment failed')
      }
    } catch (error) {
      toast.error('Failed to enrich rule')
    } finally {
      setEnriching(false)
      setIsLoading(false)
      setLoadingMessage('')
    }
  }

  const handleApplyRule = async () => {
    if (!currentAnalysis) return
    if (!query.trim()) {
      toast.error('Rule query is required')
      return
    }

    setIsLoading(true)
    setLoadingMessage('Uploading rule to Elastic SIEM...')

    try {
      const webhookUrl = `${n8nConfig.base_url}${n8nConfig.webhook_elastic_rule}`

      const rule = buildRule()

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
        tags: ['purple-team', 'manual', ...rule.mitre],
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
        setApplied(true)

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
        <div className="cyber-card rounded-2xl p-6 space-y-5">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-display tracking-wider text-slate">RULE NAME</label>
              <input
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                className="cyber-input"
                placeholder="Manual rule name"
              />
            </div>
            <div>
              <label className="text-xs font-display tracking-wider text-slate">SEVERITY</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as DetectionRule['severity'])}
                className="cyber-input"
              >
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
                <option value="critical">critical</option>
              </select>
            </div>
            <div className="lg:col-span-2">
              <label className="text-xs font-display tracking-wider text-slate">DESCRIPTION</label>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="cyber-input"
                placeholder="What this rule detects"
              />
            </div>
            <div className="lg:col-span-2">
              <label className="text-xs font-display tracking-wider text-slate">INDEX (comma-separated)</label>
              <input
                value={index}
                onChange={(e) => setIndex(e.target.value)}
                className="cyber-input font-mono text-xs"
                placeholder="logs-*, winlogbeat-*"
              />
            </div>
            <div className="lg:col-span-2">
              <label className="text-xs font-display tracking-wider text-slate">MITRE TECHNIQUES (comma-separated)</label>
              <input
                value={mitreInput}
                onChange={(e) => setMitreInput(e.target.value)}
                className="cyber-input font-mono text-xs"
                placeholder="T1059,T1047"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-display tracking-wider text-slate">SIEM RULE / QUERY</span>
              <button
                onClick={() => copyToClipboard(query)}
                className="flex items-center gap-1 text-xs text-cyber-purple hover:text-white transition-colors"
              >
                <DocumentDuplicateIcon className="w-4 h-4" />
                Copy
              </button>
            </div>
            <textarea
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="cyber-input font-mono text-sm"
              rows={10}
              placeholder="Paste/write KQL, EQL, or query here..."
            />
          </div>

          {enrichment && (
            <div className="p-4 bg-cyber-purple/5 border border-cyber-purple/20 rounded-xl">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <SparklesIcon className="w-5 h-5 text-cyber-purple" />
                  <span className="text-xs font-display tracking-wider text-cyber-purple">THREAT INTELLIGENCE ENRICHMENT</span>
                </div>
                <button
                  onClick={() => copyToClipboard(enrichment)}
                  className="flex items-center gap-1 text-xs text-cyber-purple hover:text-white transition-colors"
                >
                  <DocumentDuplicateIcon className="w-4 h-4" />
                  Copy
                </button>
              </div>
              <pre className="text-sm text-white whitespace-pre-wrap">{enrichment}</pre>
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <motion.button
              onClick={handleEnrichRule}
              disabled={enriching}
              className="flex-1 cyber-btn-outline flex items-center justify-center gap-2"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <SparklesIcon className="w-5 h-5" />
              {enriching ? 'ENRICHING...' : 'ENRICH TI'}
            </motion.button>
            <motion.button
              onClick={handleApplyRule}
              className="flex-1 cyber-btn-success flex items-center justify-center gap-2"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <CloudArrowUpIcon className="w-5 h-5" />
              APPLY TO ELASTIC
            </motion.button>
          </div>

          {applied && (
            <div className="text-neon-green text-sm font-display tracking-wider">
              APPLIED
            </div>
          )}
        </div>
      ) : (
        <div className="cyber-card rounded-2xl p-12 text-center">
          <ShieldExclamationIcon className="w-16 h-16 mx-auto mb-4 text-slate opacity-50" />
          <h2 className="font-display text-xl font-semibold tracking-wider text-white mb-2">
            No Analysis Selected
          </h2>
          <p className="text-slate">
            Select an analysis from the Ingest page to use the SIEM rule editor
          </p>
        </div>
      )}
    </div>
  )
}
