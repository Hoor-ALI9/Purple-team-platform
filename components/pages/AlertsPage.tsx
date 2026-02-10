'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { usePurpleTeamStore, ElasticAlert } from '@/lib/store'
import toast from 'react-hot-toast'
import {
  BellAlertIcon,
  ArrowPathIcon,
  AdjustmentsHorizontalIcon,
  FunnelIcon,
  ChartBarIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XMarkIcon,
  MagnifyingGlassIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
} from '@heroicons/react/24/outline'

export default function AlertsPage() {
  const { elasticAlerts, setElasticAlerts, n8nConfig, currentAnalysis } = usePurpleTeamStore()
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [tuningAlert, setTuningAlert] = useState<ElasticAlert | null>(null)
  const [tuningNotes, setTuningNotes] = useState('')

  const fetchAlerts = async () => {
    setIsRefreshing(true)
    
    try {
      // In production, this would call your n8n webhook to pull alerts from Elastic
      const webhookUrl = `${n8nConfig.base_url}/webhook/fetch-alerts`
      
      // Simulated alerts for demo
      const mockAlerts: ElasticAlert[] = [
        {
          id: 'alert_1',
          rule_id: 'rule_samba_exploit',
          rule_name: 'Samba usermap_script Exploitation',
          severity: 'critical',
          timestamp: new Date().toISOString(),
          host: '192.168.204.140',
          description: 'Detected exploitation attempt of CVE-2007-2447',
          mitre_tactic: 'Initial Access',
          mitre_technique: 'T1190',
          count: 3,
        },
        {
          id: 'alert_2',
          rule_id: 'rule_reverse_shell',
          rule_name: 'Reverse Shell Connection Detected',
          severity: 'high',
          timestamp: new Date(Date.now() - 300000).toISOString(),
          host: '192.168.204.140',
          description: 'Outbound connection to known C2 pattern detected',
          mitre_tactic: 'Command and Control',
          mitre_technique: 'T1059',
          count: 1,
        },
        {
          id: 'alert_3',
          rule_id: 'rule_suspicious_process',
          rule_name: 'Suspicious Process Execution',
          severity: 'medium',
          timestamp: new Date(Date.now() - 600000).toISOString(),
          host: '192.168.204.140',
          description: 'Unusual process spawned from web service',
          mitre_tactic: 'Execution',
          mitre_technique: 'T1059.004',
          count: 5,
        },
      ]

      setElasticAlerts(mockAlerts)
      toast.success('Alerts refreshed')
    } catch (error) {
      toast.error('Failed to fetch alerts')
    } finally {
      setIsRefreshing(false)
    }
  }

  const filteredAlerts = elasticAlerts.filter(alert => {
    const matchesSeverity = selectedSeverity === 'all' || alert.severity === selectedSeverity
    const matchesSearch = alert.rule_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          alert.host.includes(searchQuery) ||
                          alert.description.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesSeverity && matchesSearch
  })

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-neon-red/20 text-neon-red border-neon-red/30'
      case 'high': return 'bg-neon-orange/20 text-neon-orange border-neon-orange/30'
      case 'medium': return 'bg-neon-yellow/20 text-neon-yellow border-neon-yellow/30'
      default: return 'bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30'
    }
  }

  const getRuleMatchStatus = (alert: ElasticAlert) => {
    if (!currentAnalysis) return null
    const matchingRule = currentAnalysis.detection_rules.find(
      r => r.rule_name.toLowerCase().includes(alert.rule_name.toLowerCase().split(' ')[0])
    )
    return matchingRule ? 'matched' : null
  }

  const handleTuneRule = async () => {
    if (!tuningAlert || !tuningNotes) {
      toast.error('Please add tuning notes')
      return
    }

    try {
      // Send tuning request to n8n
      toast.success('Tuning request submitted')
      setTuningAlert(null)
      setTuningNotes('')
    } catch (error) {
      toast.error('Failed to submit tuning request')
    }
  }

  // Stats
  const stats = {
    total: elasticAlerts.length,
    critical: elasticAlerts.filter(a => a.severity === 'critical').length,
    high: elasticAlerts.filter(a => a.severity === 'high').length,
    medium: elasticAlerts.filter(a => a.severity === 'medium').length,
    low: elasticAlerts.filter(a => a.severity === 'low').length,
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-wider text-white flex items-center gap-3">
            <BellAlertIcon className="w-8 h-8 text-neon-red" />
            SECURITY ALERTS
          </h1>
          <p className="text-slate mt-1">
            Monitor alerts from Elastic SIEM and tune detection rules
          </p>
        </div>
        <motion.button
          onClick={fetchAlerts}
          disabled={isRefreshing}
          className="cyber-btn flex items-center gap-2"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <ArrowPathIcon className={`w-5 h-5 ${isRefreshing ? 'animate-spin' : ''}`} />
          {isRefreshing ? 'REFRESHING...' : 'REFRESH'}
        </motion.button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="cyber-card rounded-xl p-4"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-display tracking-wider text-slate">TOTAL</span>
            <ChartBarIcon className="w-5 h-5 text-cyber-purple" />
          </div>
          <p className="text-3xl font-display font-bold text-white mt-2">{stats.total}</p>
        </motion.div>

        {[
          { label: 'CRITICAL', count: stats.critical, color: 'neon-red' },
          { label: 'HIGH', count: stats.high, color: 'neon-orange' },
          { label: 'MEDIUM', count: stats.medium, color: 'neon-yellow' },
          { label: 'LOW', count: stats.low, color: 'cyber-cyan' },
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: (i + 1) * 0.1 }}
            className="cyber-card rounded-xl p-4"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-display tracking-wider text-slate">{stat.label}</span>
              <div className={`w-3 h-3 rounded-full bg-${stat.color}`} />
            </div>
            <p className={`text-3xl font-display font-bold text-${stat.color} mt-2`}>{stat.count}</p>
          </motion.div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4">
        <div className="relative flex-1 min-w-64">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate" />
          <input
            type="text"
            placeholder="Search alerts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="cyber-input pl-10"
          />
        </div>
        <div className="flex gap-2">
          {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
            <button
              key={severity}
              onClick={() => setSelectedSeverity(severity)}
              className={`
                px-4 py-2 rounded-lg font-display text-sm tracking-wider transition-all duration-200
                ${selectedSeverity === severity
                  ? severity === 'all'
                    ? 'bg-cyber-purple/20 text-cyber-purple border border-cyber-purple/30'
                    : `bg-${severity === 'critical' ? 'neon-red' : severity === 'high' ? 'neon-orange' : severity === 'medium' ? 'neon-yellow' : 'cyber-cyan'}/20 text-${severity === 'critical' ? 'neon-red' : severity === 'high' ? 'neon-orange' : severity === 'medium' ? 'neon-yellow' : 'cyber-cyan'} border border-${severity === 'critical' ? 'neon-red' : severity === 'high' ? 'neon-orange' : severity === 'medium' ? 'neon-yellow' : 'cyber-cyan'}/30`
                  : 'bg-graphite/30 text-slate hover:text-white border border-transparent'
                }
              `}
            >
              {severity.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Alerts List */}
      <div className="space-y-4">
        {filteredAlerts.length === 0 ? (
          <div className="cyber-card rounded-2xl p-12 text-center">
            <BellAlertIcon className="w-16 h-16 mx-auto mb-4 text-slate opacity-50" />
            <h2 className="font-display text-xl font-semibold tracking-wider text-white mb-2">
              No Alerts Found
            </h2>
            <p className="text-slate">
              {elasticAlerts.length === 0 
                ? 'Click refresh to fetch alerts from Elastic SIEM'
                : 'No alerts match your current filters'}
            </p>
          </div>
        ) : (
          filteredAlerts.map((alert, index) => (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
              className="cyber-card rounded-2xl p-6"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="font-display text-lg font-semibold tracking-wider text-white">
                      {alert.rule_name}
                    </h3>
                    <span className={`cyber-badge ${getSeverityColor(alert.severity)}`}>
                      {alert.severity.toUpperCase()}
                    </span>
                    {getRuleMatchStatus(alert) === 'matched' && (
                      <span className="cyber-badge-green flex items-center gap-1">
                        <CheckCircleIcon className="w-4 h-4" />
                        RULE MATCH
                      </span>
                    )}
                  </div>
                  <p className="text-slate mb-3">{alert.description}</p>
                  
                  <div className="flex flex-wrap gap-4 text-sm">
                    <div className="flex items-center gap-2">
                      <span className="text-slate">Host:</span>
                      <span className="font-mono text-white">{alert.host}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-slate">Count:</span>
                      <span className="font-mono text-white flex items-center gap-1">
                        {alert.count}
                        {alert.count > 3 && <ArrowTrendingUpIcon className="w-4 h-4 text-neon-red" />}
                      </span>
                    </div>
                    {alert.mitre_technique && (
                      <div className="flex items-center gap-2">
                        <span className="text-slate">MITRE:</span>
                        <span className="px-2 py-1 bg-cyber-purple/20 text-cyber-purple text-xs rounded font-mono">
                          {alert.mitre_technique}
                        </span>
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <span className="text-slate">Time:</span>
                      <span className="font-mono text-white">
                        {new Date(alert.timestamp).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex gap-2 ml-4">
                  <motion.button
                    onClick={() => setTuningAlert(alert)}
                    className="cyber-btn-outline text-sm py-2 px-4 flex items-center gap-2"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <AdjustmentsHorizontalIcon className="w-4 h-4" />
                    TUNE
                  </motion.button>
                </div>
              </div>
            </motion.div>
          ))
        )}
      </div>

      {/* Tuning Modal */}
      <AnimatePresence>
        {tuningAlert && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-void/90 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setTuningAlert(null)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="cyber-card rounded-2xl p-6 max-w-lg w-full"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-xl font-semibold tracking-wider text-white flex items-center gap-2">
                  <AdjustmentsHorizontalIcon className="w-6 h-6 text-cyber-purple" />
                  TUNE RULE
                </h2>
                <button
                  onClick={() => setTuningAlert(null)}
                  className="p-2 text-slate hover:text-white transition-colors"
                >
                  <XMarkIcon className="w-6 h-6" />
                </button>
              </div>

              <div className="mb-4 p-4 bg-graphite/30 rounded-lg">
                <p className="font-display font-semibold text-white mb-1">{tuningAlert.rule_name}</p>
                <p className="text-sm text-slate">Alert count: {tuningAlert.count}</p>
              </div>

              <div className="mb-4">
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  TUNING ACTION
                </label>
                <select className="cyber-select">
                  <option value="reduce_noise">Reduce False Positives</option>
                  <option value="add_exception">Add Exception</option>
                  <option value="modify_threshold">Modify Threshold</option>
                  <option value="disable_rule">Disable Rule</option>
                </select>
              </div>

              <div className="mb-6">
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  TUNING NOTES
                </label>
                <textarea
                  value={tuningNotes}
                  onChange={(e) => setTuningNotes(e.target.value)}
                  placeholder="Describe why this rule needs tuning..."
                  rows={4}
                  className="cyber-input"
                />
              </div>

              <div className="flex gap-3">
                <button onClick={handleTuneRule} className="flex-1 cyber-btn">
                  SUBMIT TUNING
                </button>
                <button onClick={() => setTuningAlert(null)} className="cyber-btn-outline">
                  CANCEL
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

