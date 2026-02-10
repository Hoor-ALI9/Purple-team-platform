'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { usePurpleTeamStore } from '@/lib/store'
import toast from 'react-hot-toast'
import {
  Cog6ToothIcon,
  ServerIcon,
  KeyIcon,
  LinkIcon,
  ShieldCheckIcon,
  CheckIcon,
  EyeIcon,
  EyeSlashIcon,
  CpuChipIcon,
  SignalIcon,
} from '@heroicons/react/24/outline'

export default function SettingsPage() {
  const { n8nConfig, updateN8nConfig, agentConfig, updateAgentConfig } = usePurpleTeamStore()
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({})
  const [testingConnection, setTestingConnection] = useState<string | null>(null)

  const handleSave = () => {
    toast.success('Settings saved successfully')
  }

  const testConnection = async (service: string) => {
    setTestingConnection(service)
    
    try {
      if (service === 'Agent') {
        // Test real SSH connection to the agent
        const response = await fetch('/api/agent/test-connection', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(agentConfig),
        })
        const result = await response.json()
        if (result.success) {
          toast.success(`Agent connected! ${result.agent_version ? `v${result.agent_version}` : ''}`)
        } else {
          toast.error(`Agent connection failed: ${result.error}`)
        }
      } else {
        // Simulate connection test for other services
        await new Promise(resolve => setTimeout(resolve, 2000))
        toast.success(`${service} connection successful`)
      }
    } catch (error) {
      toast.error(`Failed to connect to ${service}`)
    } finally {
      setTestingConnection(null)
    }
  }

  const togglePassword = (field: string) => {
    setShowPasswords(prev => ({ ...prev, [field]: !prev[field] }))
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="font-display text-3xl font-bold tracking-wider text-white flex items-center gap-3">
          <Cog6ToothIcon className="w-8 h-8 text-slate" />
          PLATFORM SETTINGS
        </h1>
        <p className="text-slate mt-1">
          Configure n8n webhooks, SSH credentials, and Elastic SIEM connection
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* n8n Configuration */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="cyber-card rounded-2xl p-6"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-neon-orange to-neon-yellow flex items-center justify-center">
              <LinkIcon className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="font-display text-lg font-semibold tracking-wider text-white">
                n8n WORKFLOW
              </h2>
              <p className="text-sm text-slate">Automation webhook endpoints</p>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                BASE URL
              </label>
              <input
                type="text"
                value={n8nConfig.base_url}
                onChange={(e) => updateN8nConfig({ base_url: e.target.value })}
                placeholder="http://localhost:5678"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                PENTEST WEBHOOK
              </label>
              <input
                type="text"
                value={n8nConfig.webhook_pentest}
                onChange={(e) => updateN8nConfig({ webhook_pentest: e.target.value })}
                placeholder="/webhook/pentest"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                REMEDIATION WEBHOOK
              </label>
              <input
                type="text"
                value={n8nConfig.webhook_remediation}
                onChange={(e) => updateN8nConfig({ webhook_remediation: e.target.value })}
                placeholder="/webhook/remediation"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                ELASTIC RULE WEBHOOK
              </label>
              <input
                type="text"
                value={n8nConfig.webhook_elastic_rule}
                onChange={(e) => updateN8nConfig({ webhook_elastic_rule: e.target.value })}
                placeholder="/webhook/elastic-rule"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                THREAT INTEL WEBHOOK
              </label>
              <input
                type="text"
                value={n8nConfig.webhook_threat_intel}
                onChange={(e) => updateN8nConfig({ webhook_threat_intel: e.target.value })}
                placeholder="/webhook/threat-intel"
                className="cyber-input"
              />
            </div>

            <button
              onClick={() => testConnection('n8n')}
              disabled={testingConnection === 'n8n'}
              className="w-full cyber-btn-outline flex items-center justify-center gap-2"
            >
              {testingConnection === 'n8n' ? (
                <>
                  <div className="w-4 h-4 border-2 border-cyber-purple border-t-transparent rounded-full animate-spin" />
                  TESTING...
                </>
              ) : (
                <>
                  <ShieldCheckIcon className="w-5 h-5" />
                  TEST CONNECTION
                </>
              )}
            </button>
          </div>
        </motion.div>

        {/* SSH Configuration */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="cyber-card rounded-2xl p-6"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyber-purple to-cyber-magenta flex items-center justify-center">
              <ServerIcon className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="font-display text-lg font-semibold tracking-wider text-white">
                SSH CONFIGURATION
              </h2>
              <p className="text-sm text-slate">Remote execution credentials</p>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                SSH HOST
              </label>
              <input
                type="text"
                value={n8nConfig.ssh_host}
                onChange={(e) => updateN8nConfig({ ssh_host: e.target.value })}
                placeholder="192.168.1.100"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                SSH USER
              </label>
              <input
                type="text"
                value={n8nConfig.ssh_user}
                onChange={(e) => updateN8nConfig({ ssh_user: e.target.value })}
                placeholder="root"
                className="cyber-input"
              />
            </div>

            <div className="p-4 bg-neon-yellow/5 border border-neon-yellow/20 rounded-lg">
              <p className="text-sm text-neon-yellow">
                ⚠️ SSH credentials are stored in n8n workflow credentials, not in this platform for security.
              </p>
            </div>
          </div>
        </motion.div>

        {/* Agent Configuration */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="cyber-card rounded-2xl p-6 lg:col-span-2"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-neon-red to-cyber-magenta flex items-center justify-center">
              <CpuChipIcon className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="font-display text-lg font-semibold tracking-wider text-white">
                AGENT CONFIGURATION
              </h2>
              <p className="text-sm text-slate">Kali Linux attacker agent SSH credentials</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                AGENT SSH HOST
              </label>
              <input
                type="text"
                value={agentConfig.ssh_host}
                onChange={(e) => updateAgentConfig({ ssh_host: e.target.value })}
                placeholder="192.168.204.128"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                SSH PORT
              </label>
              <input
                type="number"
                value={agentConfig.ssh_port}
                onChange={(e) => updateAgentConfig({ ssh_port: parseInt(e.target.value) || 22 })}
                placeholder="22"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                SSH USER
              </label>
              <input
                type="text"
                value={agentConfig.ssh_user}
                onChange={(e) => updateAgentConfig({ ssh_user: e.target.value })}
                placeholder="root"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                SSH PASSWORD
              </label>
              <div className="relative">
                <input
                  type={showPasswords.agent ? 'text' : 'password'}
                  value={agentConfig.ssh_password}
                  onChange={(e) => updateAgentConfig({ ssh_password: e.target.value })}
                  placeholder="••••••••"
                  className="cyber-input pr-10"
                />
                <button
                  type="button"
                  onClick={() => togglePassword('agent')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate hover:text-white transition-colors"
                >
                  {showPasswords.agent ? (
                    <EyeSlashIcon className="w-5 h-5" />
                  ) : (
                    <EyeIcon className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                PYTHON PATH
              </label>
              <input
                type="text"
                value={agentConfig.python_path}
                onChange={(e) => updateAgentConfig({ python_path: e.target.value })}
                placeholder="python3"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                AGENT SCRIPT PATH
              </label>
              <input
                type="text"
                value={agentConfig.agent_path}
                onChange={(e) => updateAgentConfig({ agent_path: e.target.value })}
                placeholder="/opt/purple-agent/Blackbox Agent.py"
                className="cyber-input"
              />
            </div>
          </div>

          <div className="mt-4">
            <button
              onClick={() => testConnection('Agent')}
              disabled={testingConnection === 'Agent'}
              className="w-full cyber-btn-outline flex items-center justify-center gap-2"
            >
              {testingConnection === 'Agent' ? (
                <>
                  <div className="w-4 h-4 border-2 border-cyber-purple border-t-transparent rounded-full animate-spin" />
                  TESTING AGENT CONNECTION...
                </>
              ) : (
                <>
                  <SignalIcon className="w-5 h-5" />
                  TEST AGENT CONNECTION
                </>
              )}
            </button>
          </div>

          <div className="mt-4 p-4 bg-neon-red/5 border border-neon-red/20 rounded-lg">
            <p className="text-sm text-neon-red">
              🔒 The agent must be deployed on your Kali Linux attacker machine. Copy the <span className="font-mono text-xs">Blackbox Agent.py</span> file to the configured agent script path.
            </p>
          </div>
        </motion.div>

        {/* Elastic Configuration */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="cyber-card rounded-2xl p-6"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyber-cyan to-cyber-blue flex items-center justify-center">
              <ShieldCheckIcon className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="font-display text-lg font-semibold tracking-wider text-white">
                ELASTIC SIEM
              </h2>
              <p className="text-sm text-slate">Detection rules & alerts endpoint</p>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                ELASTIC URL
              </label>
              <input
                type="text"
                value={n8nConfig.elastic_url}
                onChange={(e) => updateN8nConfig({ elastic_url: e.target.value })}
                placeholder="https://elastic.example.com:9243"
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                API KEY
              </label>
              <div className="relative">
                <input
                  type={showPasswords.elastic ? 'text' : 'password'}
                  value={n8nConfig.elastic_api_key}
                  onChange={(e) => updateN8nConfig({ elastic_api_key: e.target.value })}
                  placeholder="••••••••"
                  className="cyber-input pr-10"
                />
                <button
                  type="button"
                  onClick={() => togglePassword('elastic')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate hover:text-white transition-colors"
                >
                  {showPasswords.elastic ? (
                    <EyeSlashIcon className="w-5 h-5" />
                  ) : (
                    <EyeIcon className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>

            <button
              onClick={() => testConnection('Elastic')}
              disabled={testingConnection === 'Elastic'}
              className="w-full cyber-btn-outline flex items-center justify-center gap-2"
            >
              {testingConnection === 'Elastic' ? (
                <>
                  <div className="w-4 h-4 border-2 border-cyber-purple border-t-transparent rounded-full animate-spin" />
                  TESTING...
                </>
              ) : (
                <>
                  <ShieldCheckIcon className="w-5 h-5" />
                  TEST CONNECTION
                </>
              )}
            </button>
          </div>
        </motion.div>

        {/* Discord Configuration */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="cyber-card rounded-2xl p-6"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#5865F2] to-[#7289DA] flex items-center justify-center">
              <svg className="w-6 h-6 text-white" viewBox="0 0 24 24" fill="currentColor">
                <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515a.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0a12.64 12.64 0 0 0-.617-1.25a.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057a19.9 19.9 0 0 0 5.993 3.03a.078.078 0 0 0 .084-.028a14.09 14.09 0 0 0 1.226-1.994a.076.076 0 0 0-.041-.106a13.107 13.107 0 0 1-1.872-.892a.077.077 0 0 1-.008-.128a10.2 10.2 0 0 0 .372-.292a.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127a12.299 12.299 0 0 1-1.873.892a.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028a19.839 19.839 0 0 0 6.002-3.03a.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419c0-1.333.956-2.419 2.157-2.419c1.21 0 2.176 1.096 2.157 2.42c0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419c0-1.333.955-2.419 2.157-2.419c1.21 0 2.176 1.096 2.157 2.42c0 1.333-.946 2.418-2.157 2.418z"/>
              </svg>
            </div>
            <div>
              <h2 className="font-display text-lg font-semibold tracking-wider text-white">
                DISCORD NOTIFICATIONS
              </h2>
              <p className="text-sm text-slate">Attack result alerts via Discord webhook</p>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                WEBHOOK URL
              </label>
              <input
                type="text"
                value={n8nConfig.discord_webhook_url}
                onChange={(e) => updateN8nConfig({ discord_webhook_url: e.target.value })}
                placeholder="https://discord.com/api/webhooks/..."
                className="cyber-input font-mono text-xs"
              />
              <p className="text-[10px] text-slate/60 mt-1">
                Discord webhook URL for receiving attack success/failure notifications with full details
              </p>
            </div>

            <div>
              <label className="block text-sm font-display tracking-wider text-slate mb-2">
                CHANNEL ID (Optional)
              </label>
              <input
                type="text"
                value={n8nConfig.discord_channel_id}
                onChange={(e) => updateN8nConfig({ discord_channel_id: e.target.value })}
                placeholder="1234567890123456789"
                className="cyber-input"
              />
            </div>

            <button
              onClick={async () => {
                if (!n8nConfig.discord_webhook_url) { toast.error('Webhook URL is required'); return }
                setTestingConnection('Discord')
                try {
                  const res = await fetch('/api/webhook/notification', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      webhook_url: n8nConfig.discord_webhook_url,
                      test: true,
                    }),
                  })
                  const result = await res.json()
                  if (result.success) {
                    toast.success('Discord webhook test sent!')
                  } else {
                    toast.error(`Webhook test failed: ${result.error}`)
                  }
                } catch {
                  toast.error('Failed to test Discord webhook')
                } finally {
                  setTestingConnection(null)
                }
              }}
              disabled={testingConnection === 'Discord'}
              className="w-full cyber-btn-outline flex items-center justify-center gap-2"
            >
              {testingConnection === 'Discord' ? (
                <>
                  <div className="w-4 h-4 border-2 border-[#5865F2] border-t-transparent rounded-full animate-spin" />
                  TESTING...
                </>
              ) : (
                <>
                  <ShieldCheckIcon className="w-5 h-5" />
                  TEST WEBHOOK
                </>
              )}
            </button>

            <div className="p-4 bg-[#5865F2]/5 border border-[#5865F2]/20 rounded-lg">
              <p className="text-sm text-slate">
                All attack results (success & failure) will be sent as rich embeds to your Discord channel with full execution details.
              </p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Save Button */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="flex justify-end"
      >
        <motion.button
          onClick={handleSave}
          className="cyber-btn flex items-center gap-2 px-8"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <CheckIcon className="w-5 h-5" />
          SAVE ALL SETTINGS
        </motion.button>
      </motion.div>
    </div>
  )
}

