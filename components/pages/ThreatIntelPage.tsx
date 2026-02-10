'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { usePurpleTeamStore, ThreatIntelConfig } from '@/lib/store'
import toast from 'react-hot-toast'
import {
  GlobeAltIcon,
  PlusIcon,
  TrashIcon,
  PencilIcon,
  CheckIcon,
  XMarkIcon,
  LinkIcon,
  KeyIcon,
  DocumentTextIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'

export default function ThreatIntelPage() {
  const {
    threatIntelConfigs,
    addThreatIntelConfig,
    updateThreatIntelConfig,
    removeThreatIntelConfig,
  } = usePurpleTeamStore()

  const [isAddingNew, setIsAddingNew] = useState(false)
  const [editingConfig, setEditingConfig] = useState<string | null>(null)
  const [newConfig, setNewConfig] = useState<Partial<ThreatIntelConfig>>({
    name: '',
    endpoint: '',
    api_key: '',
    enabled: true,
    data_mapping: {},
  })
  const [testingEndpoint, setTestingEndpoint] = useState<string | null>(null)

  const handleAddConfig = () => {
    if (!newConfig.name || !newConfig.endpoint) {
      toast.error('Name and endpoint are required')
      return
    }

    addThreatIntelConfig({
      id: `ti_${Date.now()}`,
      name: newConfig.name,
      endpoint: newConfig.endpoint,
      api_key: newConfig.api_key,
      enabled: newConfig.enabled ?? true,
      data_mapping: newConfig.data_mapping || {},
    })

    setNewConfig({ name: '', endpoint: '', api_key: '', enabled: true, data_mapping: {} })
    setIsAddingNew(false)
    toast.success('Threat intel source added')
  }

  const handleTestConnection = async (config: ThreatIntelConfig) => {
    setTestingEndpoint(config.id)
    
    try {
      // Simulate connection test
      await new Promise(resolve => setTimeout(resolve, 2000))
      toast.success(`Connection to ${config.name} successful`)
    } catch (error) {
      toast.error(`Failed to connect to ${config.name}`)
    } finally {
      setTestingEndpoint(null)
    }
  }

  const handleToggleEnabled = (id: string, enabled: boolean) => {
    updateThreatIntelConfig(id, { enabled })
    toast.success(enabled ? 'Source enabled' : 'Source disabled')
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-wider text-white flex items-center gap-3">
            <GlobeAltIcon className="w-8 h-8 text-neon-orange" />
            THREAT INTELLIGENCE
          </h1>
          <p className="text-slate mt-1">
            Configure threat intelligence feeds for rule enrichment and IOC correlation
          </p>
        </div>
        <motion.button
          onClick={() => setIsAddingNew(true)}
          className="cyber-btn flex items-center gap-2"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <PlusIcon className="w-5 h-5" />
          ADD SOURCE
        </motion.button>
      </div>

      {/* Add New Form */}
      <AnimatePresence>
        {isAddingNew && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="cyber-card rounded-2xl p-6 border-2 border-cyber-purple/50"
          >
            <h2 className="font-display text-lg font-semibold tracking-wider text-white mb-4">
              ADD NEW THREAT INTEL SOURCE
            </h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  SOURCE NAME
                </label>
                <input
                  type="text"
                  value={newConfig.name}
                  onChange={(e) => setNewConfig(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="e.g., AlienVault OTX"
                  className="cyber-input"
                />
              </div>
              <div>
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  API ENDPOINT
                </label>
                <input
                  type="text"
                  value={newConfig.endpoint}
                  onChange={(e) => setNewConfig(prev => ({ ...prev, endpoint: e.target.value }))}
                  placeholder="https://api.example.com/v1"
                  className="cyber-input"
                />
              </div>
              <div className="md:col-span-2">
                <label className="block text-sm font-display tracking-wider text-slate mb-2">
                  API KEY (Optional)
                </label>
                <input
                  type="password"
                  value={newConfig.api_key}
                  onChange={(e) => setNewConfig(prev => ({ ...prev, api_key: e.target.value }))}
                  placeholder="••••••••"
                  className="cyber-input"
                />
              </div>
            </div>

            <div className="flex gap-3">
              <button onClick={handleAddConfig} className="cyber-btn-success">
                <CheckIcon className="w-5 h-5 mr-2 inline" />
                ADD SOURCE
              </button>
              <button onClick={() => setIsAddingNew(false)} className="cyber-btn-outline">
                <XMarkIcon className="w-5 h-5 mr-2 inline" />
                CANCEL
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Configured Sources */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {threatIntelConfigs.map((config, index) => (
          <motion.div
            key={config.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className={`cyber-card rounded-2xl p-6 ${
              config.enabled ? '' : 'opacity-50'
            }`}
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className={`
                  w-12 h-12 rounded-xl flex items-center justify-center
                  ${config.enabled 
                    ? 'bg-gradient-to-br from-neon-orange to-neon-yellow' 
                    : 'bg-graphite'
                  }
                `}>
                  <GlobeAltIcon className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h3 className="font-display font-semibold tracking-wider text-white">
                    {config.name}
                  </h3>
                  <div className="flex items-center gap-2 mt-1">
                    <div className={`w-2 h-2 rounded-full ${config.enabled ? 'bg-neon-green' : 'bg-slate'}`} />
                    <span className="text-xs text-slate">
                      {config.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </div>
                </div>
              </div>
              
              {/* Toggle Switch */}
              <button
                onClick={() => handleToggleEnabled(config.id, !config.enabled)}
                className={`
                  relative w-12 h-6 rounded-full transition-colors duration-200
                  ${config.enabled ? 'bg-neon-green' : 'bg-graphite'}
                `}
              >
                <motion.div
                  className="absolute top-1 w-4 h-4 bg-white rounded-full shadow"
                  animate={{ left: config.enabled ? 28 : 4 }}
                  transition={{ duration: 0.2 }}
                />
              </button>
            </div>

            {/* Endpoint */}
            <div className="mb-4">
              <div className="flex items-center gap-2 mb-1">
                <LinkIcon className="w-4 h-4 text-slate" />
                <span className="text-xs font-display tracking-wider text-slate">ENDPOINT</span>
              </div>
              <p className="font-mono text-sm text-white truncate">{config.endpoint}</p>
            </div>

            {/* API Key Status */}
            <div className="mb-4">
              <div className="flex items-center gap-2 mb-1">
                <KeyIcon className="w-4 h-4 text-slate" />
                <span className="text-xs font-display tracking-wider text-slate">API KEY</span>
              </div>
              <p className="text-sm text-white">
                {config.api_key ? '••••••••••••' : 'Not configured'}
              </p>
            </div>

            {/* Data Mapping */}
            {Object.keys(config.data_mapping).length > 0 && (
              <div className="mb-4">
                <div className="flex items-center gap-2 mb-2">
                  <DocumentTextIcon className="w-4 h-4 text-slate" />
                  <span className="text-xs font-display tracking-wider text-slate">DATA MAPPING</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(config.data_mapping).map(([key, value]) => (
                    <span
                      key={key}
                      className="px-2 py-1 bg-graphite/50 text-xs rounded font-mono text-slate"
                    >
                      {key}: {value}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="flex gap-2 pt-4 border-t border-slate/20">
              <button
                onClick={() => handleTestConnection(config)}
                disabled={testingEndpoint === config.id}
                className="flex-1 cyber-btn-outline text-sm py-2 flex items-center justify-center gap-2"
              >
                <ArrowPathIcon className={`w-4 h-4 ${testingEndpoint === config.id ? 'animate-spin' : ''}`} />
                {testingEndpoint === config.id ? 'TESTING...' : 'TEST'}
              </button>
              <button
                onClick={() => setEditingConfig(config.id)}
                className="cyber-btn-outline text-sm py-2 px-4"
              >
                <PencilIcon className="w-4 h-4" />
              </button>
              <button
                onClick={() => {
                  removeThreatIntelConfig(config.id)
                  toast.success('Source removed')
                }}
                className="cyber-btn-danger text-sm py-2 px-4"
              >
                <TrashIcon className="w-4 h-4" />
              </button>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Empty State */}
      {threatIntelConfigs.length === 0 && (
        <div className="cyber-card rounded-2xl p-12 text-center">
          <GlobeAltIcon className="w-16 h-16 mx-auto mb-4 text-slate opacity-50" />
          <h2 className="font-display text-xl font-semibold tracking-wider text-white mb-2">
            No Threat Intel Sources
          </h2>
          <p className="text-slate mb-4">
            Add threat intelligence feeds to enrich detection rules with IOC data
          </p>
          <button
            onClick={() => setIsAddingNew(true)}
            className="cyber-btn inline-flex items-center gap-2"
          >
            <PlusIcon className="w-5 h-5" />
            ADD FIRST SOURCE
          </button>
        </div>
      )}

      {/* Quick Start Guide */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="cyber-card rounded-2xl p-6"
      >
        <h2 className="font-display text-lg font-semibold tracking-wider text-white mb-4">
          SUPPORTED INTEGRATIONS
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { name: 'AlienVault OTX', desc: 'Open Threat Exchange', color: 'from-neon-orange to-neon-yellow' },
            { name: 'VirusTotal', desc: 'File & URL Analysis', color: 'from-cyber-blue to-cyber-cyan' },
            { name: 'MISP', desc: 'Threat Intelligence Platform', color: 'from-cyber-purple to-cyber-magenta' },
            { name: 'AbuseIPDB', desc: 'IP Reputation Database', color: 'from-neon-red to-neon-orange' },
            { name: 'Shodan', desc: 'Internet-Wide Scanner', color: 'from-neon-green to-cyber-teal' },
            { name: 'Custom API', desc: 'Any REST API', color: 'from-slate to-graphite' },
          ].map((integration) => (
            <div
              key={integration.name}
              className="p-4 bg-graphite/30 rounded-xl border border-slate/20 hover:border-slate/40 transition-colors"
            >
              <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${integration.color} flex items-center justify-center mb-2`}>
                <GlobeAltIcon className="w-5 h-5 text-white" />
              </div>
              <h3 className="font-display font-semibold text-white">{integration.name}</h3>
              <p className="text-xs text-slate">{integration.desc}</p>
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  )
}

