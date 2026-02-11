import { create } from 'zustand'
import { persist } from 'zustand/middleware'

// Types
export interface AttackResult {
  execution_id: string
  attack_type: 'credentialed' | 'blackbox'
  timestamp: string
  target_ip: string
  target_port: number
  session_id?: string
  raw_output: string
  success: boolean
  os_type?: string
}

export interface AIAnalysis {
  execution_id: string
  attack_summary: {
    overview: string
    attacker_objective: string
    skill_level: string
    confidence: number
  }
  attack_timeline: Array<{
    timestamp: string
    command: string
    action: string
    intent: string
    mitre: string[]
    risk: string
  }>
  impact_assessment: {
    blast_radius: string
    assets_affected: string[]
    business_risk: string
    worst_case_scenario: string
  }
  remediation: {
    immediate: RemediationStep[]
    short_term: RemediationStep[]
    long_term: RemediationStep[]
  }
  detection_rules: DetectionRule[]
  threat_intelligence: {
    summary: string
    ioc_correlation: string[]
    confidence: number
  }
  assumptions_and_gaps: string[]
  overall_confidence: number
  cve_analysis?: CVEAnalysis[]
}

export interface CVEAnalysis {
  exploit_name: string
  cve_id: string
  what_actually_happened: string
  remediation_steps: string
  sigma_detection_queries: string
  endpoint_mitigation_commands: string
}

export interface AIPromptSettings {
  mapExploitToCVE: string
  getRemediationSteps: string
  getSigmaAndQueries: string
  getEndpointMitigationCommands: string
  getWhatActuallyHappened: string
}

export interface RemediationStep {
  id: string
  title: string
  description: string
  command: string
  target_scope: string
  expected_outcome: string
  risk_if_skipped: string
  requires_approval: boolean
  is_disruptive: boolean
  status: 'pending' | 'approved' | 'executed' | 'rejected'
}

export interface DetectionRule {
  id: string
  rule_name: string
  description: string
  index: string
  query: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  mitre: string[]
  false_positives: string
  tuning_notes: string
  status: 'draft' | 'enriched' | 'applied'
  enrichment_data?: string
}

export interface ThreatIntelConfig {
  id: string
  name: string
  endpoint: string
  api_key?: string
  enabled: boolean
  data_mapping: Record<string, string>
}

export interface ElasticAlert {
  id: string
  rule_id: string
  rule_name: string
  severity: string
  timestamp: string
  host: string
  description: string
  mitre_tactic?: string
  mitre_technique?: string
  count: number
}

export interface N8nConfig {
  base_url: string
  webhook_pentest: string
  webhook_remediation: string
  webhook_elastic_rule: string
  webhook_threat_intel: string
  ssh_host: string
  ssh_user: string
  elastic_url: string
  elastic_api_key: string
  discord_channel_id: string
  discord_webhook_url: string
}

export interface AgentConfig {
  ssh_host: string
  ssh_port: number
  ssh_user: string
  ssh_password: string
  agent_path: string
  python_path: string
}

export interface SuggestedExploit {
  id: string
  name: string
  module_path: string
  source: 'built-in' | 'searchsploit' | 'nmap-scripts'
  service: string
  port: number
  product: string
  description: string
  rank: string
  payload: string | null
  exploit_type: string
  options: Record<string, string>
  confidence: 'high' | 'medium' | 'low'
}

export interface DiscoveredHost {
  ip: string
  os: string
  os_type: string
  os_accuracy: number
  os_matches: Array<{ name: string; accuracy: number }>
  hostnames: string[]
  mac_address: string | null
  vendor: string | null
  ports: Array<{
    port: number
    protocol: string
    state: string
    service: string
    product: string
    version: string
    extrainfo: string
    cpe: string
    scripts: Record<string, string>
  }>
  suggested_exploits: SuggestedExploit[]
  scan_time: number | null
}

export interface NetworkDiscoveryResult {
  success: boolean
  module: string
  timestamp: string
  scan_config?: {
    timing: string
  }
  network_info: {
    local_ip: string
    gateway: string
    network_range: string
    interface: string
  }
  discovered_hosts: DiscoveredHost[]
  summary: {
    total_hosts: number
    total_open_ports: number
    total_suggested_exploits?: number
    os_distribution: Record<string, number>
    scan_completed_at: string
  }
  error?: string
}

// Credentialed Attack State types
export interface CredentialedConfig {
  ssh_host: string
  ssh_user: string
  ssh_password: string
  custom_command: string
}

export interface CredentialedHistoryItem {
  id: string
  timestamp: string
  status: 'running' | 'success' | 'failed'
  target: string
  module: string
  output?: string
}

// Kill Chain and Attack Vector Types
export interface KillChainStage {
  enumeration: {
    selectedHosts: Array<{
      ip: string
      os: string
      os_type: string
      ports: number[]
    }>
  }
  weaponization: {
    selectedAttacks: SuggestedExploit[]
  }
  postExploitation: {
    osType: string
    selectedModules: Array<{
      module: string
      name: string
      category: 'persistence' | 'privilege_escalation' | 'credential_access' | 'discovery' | 'collection'
    }>
    persistenceAttacks: SuggestedExploit[]
  }
  lateralMovement: {
    selectedModules: Array<{
      module: string
      name: string
      target: string
    }>
  }
}

export interface AttackVector {
  id: string
  name: string
  timestamp: string
  killChain: KillChainStage
  status: 'draft' | 'running' | 'completed' | 'failed'
  executionResults?: {
    enumeration?: { success: boolean; output?: string }
    weaponization?: { success: boolean; output?: string; sessionId?: string }
    postExploitation?: { success: boolean; output?: string }
    lateralMovement?: { success: boolean; output?: string }
  }
  endpointStatus?: Record<string, {
    stage: string
    status: 'running' | 'success' | 'failed'
    timestamp: string
  }>
}

// Store interface
interface PurpleTeamStore {
  // Navigation
  activeTab: string
  setActiveTab: (tab: string) => void

  // Attack Results
  attackResults: AttackResult[]
  currentAttack: AttackResult | null
  addAttackResult: (result: AttackResult) => void
  setCurrentAttack: (result: AttackResult | null) => void

  // AI Analysis
  analyses: AIAnalysis[]
  currentAnalysis: AIAnalysis | null
  addAnalysis: (analysis: AIAnalysis) => void
  setCurrentAnalysis: (analysis: AIAnalysis | null) => void
  updateCVEAnalysis: (analysisId: string, cveAnalysis: CVEAnalysis[]) => void

  // Remediation
  updateRemediationStatus: (analysisId: string, stepId: string, status: RemediationStep['status']) => void
  updateRemediationCommand: (analysisId: string, stepId: string, command: string) => void

  // Detection Rules
  updateRuleStatus: (analysisId: string, ruleId: string, status: DetectionRule['status']) => void
  updateRuleEnrichment: (analysisId: string, ruleId: string, enrichment: string) => void

  // Threat Intel
  threatIntelConfigs: ThreatIntelConfig[]
  addThreatIntelConfig: (config: ThreatIntelConfig) => void
  updateThreatIntelConfig: (id: string, config: Partial<ThreatIntelConfig>) => void
  removeThreatIntelConfig: (id: string) => void

  // Elastic Alerts
  elasticAlerts: ElasticAlert[]
  setElasticAlerts: (alerts: ElasticAlert[]) => void
  addElasticAlert: (alert: ElasticAlert) => void

  // n8n Configuration
  n8nConfig: N8nConfig
  updateN8nConfig: (config: Partial<N8nConfig>) => void

  // Agent Configuration
  agentConfig: AgentConfig
  updateAgentConfig: (config: Partial<AgentConfig>) => void

  // Network Discovery
  networkDiscoveryResult: NetworkDiscoveryResult | null
  setNetworkDiscoveryResult: (result: NetworkDiscoveryResult | null) => void
  isDiscoveryRunning: boolean
  setIsDiscoveryRunning: (running: boolean) => void

  // Credentialed Attack State (persisted)
  credentialedConfig: CredentialedConfig
  updateCredentialedConfig: (config: Partial<CredentialedConfig>) => void
  artConsoleOutput: string
  setArtConsoleOutput: (output: string) => void
  appendArtConsoleOutput: (text: string) => void
  credentialedHistory: CredentialedHistoryItem[]
  addCredentialedHistoryItem: (item: CredentialedHistoryItem) => void
  updateCredentialedHistoryStatus: (id: string, status: CredentialedHistoryItem['status'], output?: string) => void
  clearCredentialedHistory: () => void

  // Attack Vectors
  attackVectors: AttackVector[]
  addAttackVector: (vector: AttackVector) => void
  updateAttackVector: (id: string, updates: Partial<AttackVector>) => void
  removeAttackVector: (id: string) => void
  currentAttackVector: AttackVector | null
  setCurrentAttackVector: (vector: AttackVector | null) => void

  // Loading States
  isLoading: boolean
  setIsLoading: (loading: boolean) => void
  loadingMessage: string
  setLoadingMessage: (message: string) => void

  // Notifications
  notifications: Notification[]
  addNotification: (notification: Notification) => void
  clearNotifications: () => void

  // AI Prompt Settings
  aiPromptSettings: AIPromptSettings
  updateAIPromptSettings: (settings: Partial<AIPromptSettings>) => void
  resetAIPromptSettings: () => void
}

interface Notification {
  id: string
  type: 'success' | 'error' | 'warning' | 'info'
  title: string
  message: string
  timestamp: string
}

export const usePurpleTeamStore = create<PurpleTeamStore>()(
  persist(
    (set, get) => ({
      // Navigation
      activeTab: 'pentest',
      setActiveTab: (tab) => set({ activeTab: tab }),

      // Attack Results
      attackResults: [],
      currentAttack: null,
      addAttackResult: (result) =>
        set((state) => ({
          attackResults: [result, ...state.attackResults],
          currentAttack: result,
        })),
      setCurrentAttack: (result) => set({ currentAttack: result }),

      // AI Analysis
      analyses: [],
      currentAnalysis: null,
      addAnalysis: (analysis) =>
        set((state) => ({
          analyses: [analysis, ...state.analyses],
          currentAnalysis: analysis,
        })),
      setCurrentAnalysis: (analysis) => set({ currentAnalysis: analysis }),
      updateCVEAnalysis: (analysisId, cveAnalysis) =>
        set((state) => ({
          analyses: state.analyses.map((a) =>
            a.execution_id === analysisId ? { ...a, cve_analysis: cveAnalysis } : a
          ),
          currentAnalysis:
            state.currentAnalysis?.execution_id === analysisId
              ? { ...state.currentAnalysis, cve_analysis: cveAnalysis }
              : state.currentAnalysis,
        })),

      // Remediation
      updateRemediationStatus: (analysisId, stepId, status) =>
        set((state) => ({
          analyses: state.analyses.map((a) => {
            if (a.execution_id !== analysisId) return a
            return {
              ...a,
              remediation: {
                immediate: a.remediation.immediate.map((s) =>
                  s.id === stepId ? { ...s, status } : s
                ),
                short_term: a.remediation.short_term.map((s) =>
                  s.id === stepId ? { ...s, status } : s
                ),
                long_term: a.remediation.long_term.map((s) =>
                  s.id === stepId ? { ...s, status } : s
                ),
              },
            }
          }),
          currentAnalysis:
            state.currentAnalysis?.execution_id === analysisId
              ? {
                  ...state.currentAnalysis,
                  remediation: {
                    immediate: state.currentAnalysis.remediation.immediate.map((s) =>
                      s.id === stepId ? { ...s, status } : s
                    ),
                    short_term: state.currentAnalysis.remediation.short_term.map((s) =>
                      s.id === stepId ? { ...s, status } : s
                    ),
                    long_term: state.currentAnalysis.remediation.long_term.map((s) =>
                      s.id === stepId ? { ...s, status } : s
                    ),
                  },
                }
              : state.currentAnalysis,
        })),
      updateRemediationCommand: (analysisId, stepId, command) =>
        set((state) => ({
          analyses: state.analyses.map((a) => {
            if (a.execution_id !== analysisId) return a
            return {
              ...a,
              remediation: {
                immediate: a.remediation.immediate.map((s) =>
                  s.id === stepId ? { ...s, command } : s
                ),
                short_term: a.remediation.short_term.map((s) =>
                  s.id === stepId ? { ...s, command } : s
                ),
                long_term: a.remediation.long_term.map((s) =>
                  s.id === stepId ? { ...s, command } : s
                ),
              },
            }
          }),
        })),

      // Detection Rules
      updateRuleStatus: (analysisId, ruleId, status) =>
        set((state) => ({
          analyses: state.analyses.map((a) => {
            if (a.execution_id !== analysisId) return a
            return {
              ...a,
              detection_rules: a.detection_rules.map((r) =>
                r.id === ruleId ? { ...r, status } : r
              ),
            }
          }),
          currentAnalysis:
            state.currentAnalysis?.execution_id === analysisId
              ? {
                  ...state.currentAnalysis,
                  detection_rules: state.currentAnalysis.detection_rules.map((r) =>
                    r.id === ruleId ? { ...r, status } : r
                  ),
                }
              : state.currentAnalysis,
        })),
      updateRuleEnrichment: (analysisId, ruleId, enrichment) =>
        set((state) => ({
          analyses: state.analyses.map((a) => {
            if (a.execution_id !== analysisId) return a
            return {
              ...a,
              detection_rules: a.detection_rules.map((r) =>
                r.id === ruleId
                  ? { ...r, enrichment_data: enrichment, status: 'enriched' as const }
                  : r
              ),
            }
          }),
        })),

      // Threat Intel
      threatIntelConfigs: [
        {
          id: 'default-otx',
          name: 'AlienVault OTX',
          endpoint: 'https://otx.alienvault.com/api/v1',
          enabled: false,
          data_mapping: {
            ioc: 'indicator',
            type: 'type',
            description: 'description',
          } as Record<string, string>,
        },
        {
          id: 'default-vt',
          name: 'VirusTotal',
          endpoint: 'https://www.virustotal.com/api/v3',
          enabled: false,
          data_mapping: {
            hash: 'data.attributes.sha256',
            malicious: 'data.attributes.last_analysis_stats.malicious',
          } as Record<string, string>,
        },
      ],
      addThreatIntelConfig: (config) =>
        set((state) => ({
          threatIntelConfigs: [...state.threatIntelConfigs, config],
        })),
      updateThreatIntelConfig: (id, config) =>
        set((state) => ({
          threatIntelConfigs: state.threatIntelConfigs.map((c) =>
            c.id === id ? { ...c, ...config } : c
          ),
        })),
      removeThreatIntelConfig: (id) =>
        set((state) => ({
          threatIntelConfigs: state.threatIntelConfigs.filter((c) => c.id !== id),
        })),

      // Elastic Alerts
      elasticAlerts: [],
      setElasticAlerts: (alerts) => set({ elasticAlerts: alerts }),
      addElasticAlert: (alert) =>
        set((state) => ({ elasticAlerts: [alert, ...state.elasticAlerts] })),

      // n8n Configuration
      n8nConfig: {
        base_url: 'http://localhost:5678',
        webhook_pentest: '/webhook/pentest',
        webhook_remediation: '/webhook/remediation',
        webhook_elastic_rule: '/webhook/elastic-rule',
        webhook_threat_intel: '/webhook/threat-intel',
        ssh_host: '',
        ssh_user: '',
        elastic_url: '',
        elastic_api_key: '',
        discord_channel_id: '',
        discord_webhook_url: 'https://discord.com/api/webhooks/1469320493277384704/v8Jk-r67jABiwgiKNlGlcESHHwAYQXaskQddoTHsBPnZoEuWOf9hCnMEFF44vXpbCX_9',
      },
      updateN8nConfig: (config) =>
        set((state) => ({
          n8nConfig: { ...state.n8nConfig, ...config },
        })),

      // Agent Configuration
      agentConfig: {
        ssh_host: '',
        ssh_port: 22,
        ssh_user: 'root',
        ssh_password: '',
        agent_path: '/opt/purple-agent/Blackbox Agent.py',
        python_path: 'python3',
      },
      updateAgentConfig: (config) =>
        set((state) => ({
          agentConfig: { ...state.agentConfig, ...config },
        })),

      // Network Discovery
      networkDiscoveryResult: null,
      setNetworkDiscoveryResult: (result) => set({ networkDiscoveryResult: result }),
      isDiscoveryRunning: false,
      setIsDiscoveryRunning: (running) => set({ isDiscoveryRunning: running }),

      // Credentialed Attack State (persisted)
      credentialedConfig: {
        ssh_host: '',
        ssh_user: 'root',
        ssh_password: '',
        custom_command: '',
      },
      updateCredentialedConfig: (config) =>
        set((state) => ({
          credentialedConfig: { ...state.credentialedConfig, ...config },
        })),
      artConsoleOutput: '',
      setArtConsoleOutput: (output) => set({ artConsoleOutput: output }),
      appendArtConsoleOutput: (text) =>
        set((state) => ({ artConsoleOutput: state.artConsoleOutput + text })),
      credentialedHistory: [],
      addCredentialedHistoryItem: (item) =>
        set((state) => ({
          credentialedHistory: [item, ...state.credentialedHistory].slice(0, 100),
        })),
      updateCredentialedHistoryStatus: (id, status, output) =>
        set((state) => ({
          credentialedHistory: state.credentialedHistory.map((h) =>
            h.id === id ? { ...h, status, ...(output !== undefined ? { output } : {}) } : h
          ),
        })),
      clearCredentialedHistory: () => set({ credentialedHistory: [] }),

      // Attack Vectors
      attackVectors: [],
      addAttackVector: (vector) =>
        set((state) => ({
          attackVectors: [vector, ...state.attackVectors].slice(0, 100),
        })),
      updateAttackVector: (id, updates) =>
        set((state) => ({
          attackVectors: state.attackVectors.map((v) =>
            v.id === id ? { ...v, ...updates } : v
          ),
          currentAttackVector:
            state.currentAttackVector?.id === id
              ? { ...state.currentAttackVector, ...updates }
              : state.currentAttackVector,
        })),
      removeAttackVector: (id) =>
        set((state) => ({
          attackVectors: state.attackVectors.filter((v) => v.id !== id),
          currentAttackVector:
            state.currentAttackVector?.id === id ? null : state.currentAttackVector,
        })),
      currentAttackVector: null,
      setCurrentAttackVector: (vector) => set({ currentAttackVector: vector }),

      // Loading States
      isLoading: false,
      setIsLoading: (loading) => set({ isLoading: loading }),
      loadingMessage: '',
      setLoadingMessage: (message) => set({ loadingMessage: message }),

      // Notifications
      notifications: [],
      addNotification: (notification) =>
        set((state) => ({
          notifications: [notification, ...state.notifications].slice(0, 50),
        })),
      clearNotifications: () => set({ notifications: [] }),

      // AI Prompt Settings
      aiPromptSettings: {
        mapExploitToCVE: 'Map this security exploit or vulnerability name to its official CVE identifier(s).\nExploit name: "{exploit_name}".\nReply with only the CVE ID(s), one per line if multiple (e.g. CVE-2024-1234).\nIf no CVE exists, reply with "N/A". Do not add explanation.',
        getRemediationSteps: 'Provide clear, actionable remediation steps for {cve_id}.\nUse a numbered list. Include patching, configuration changes, and mitigation.\nKeep the response concise but complete.',
        getSigmaAndQueries: 'For {cve_id}: (1) Write one or more SIGMA detection rules (YAML) that could detect exploitation.\n(2) Then convert those SIGMA rules into concrete detection queries (e.g. KQL for Microsoft Defender, Splunk SPL, or generic SIEM query).\nOutput both the SIGMA rule(s) and the corresponding runnable queries clearly labeled.',
        getEndpointMitigationCommands: 'For {cve_id}, provide Endpoint mitigation commands that can be deployed on a compromised endpoint.\nInclude: Windows (PowerShell or CMD), and Linux (bash) where relevant.\nCommands should be runnable (e.g. disable a service, apply a registry fix, block a path).\nList each command with a short description. Do not use placeholders like <path> without example.',
        getWhatActuallyHappened: 'Based on the following pentest attack results, provide a clear and detailed summary of what actually happened during the attack.\nInclude: attack type, target information, exploitation method, successful actions, and any evidence of compromise.\n\nAttack Results:\n{attack_results}\n\nProvide a comprehensive summary of the actual attack execution and its outcomes.',
      },
      updateAIPromptSettings: (settings) =>
        set((state) => ({
          aiPromptSettings: { ...state.aiPromptSettings, ...settings },
        })),
      resetAIPromptSettings: () =>
        set({
          aiPromptSettings: {
            mapExploitToCVE: 'Map this security exploit or vulnerability name to its official CVE identifier(s).\nExploit name: "{exploit_name}".\nReply with only the CVE ID(s), one per line if multiple (e.g. CVE-2024-1234).\nIf no CVE exists, reply with "N/A". Do not add explanation.',
            getRemediationSteps: 'Provide clear, actionable remediation steps for {cve_id}.\nUse a numbered list. Include patching, configuration changes, and mitigation.\nKeep the response concise but complete.',
            getSigmaAndQueries: 'For {cve_id}: (1) Write one or more SIGMA detection rules (YAML) that could detect exploitation.\n(2) Then convert those SIGMA rules into concrete detection queries (e.g. KQL for Microsoft Defender, Splunk SPL, or generic SIEM query).\nOutput both the SIGMA rule(s) and the corresponding runnable queries clearly labeled.',
            getEndpointMitigationCommands: 'For {cve_id}, provide Endpoint mitigation commands that can be deployed on a compromised endpoint.\nInclude: Windows (PowerShell or CMD), and Linux (bash) where relevant.\nCommands should be runnable (e.g. disable a service, apply a registry fix, block a path).\nList each command with a short description. Do not use placeholders like <path> without example.',
            getWhatActuallyHappened: 'Based on the following pentest attack results, provide a clear and detailed summary of what actually happened during the attack.\nInclude: attack type, target information, exploitation method, successful actions, and any evidence of compromise.\n\nExploit/Vulnerability: {exploit_name}\n\nAttack Results:\n{attack_results}\n\nProvide a comprehensive summary of the actual attack execution and its outcomes.',
          },
        }),
    }),
    {
      name: 'purple-team-storage',
      partialize: (state) => ({
        attackResults: state.attackResults,
        analyses: state.analyses,
        threatIntelConfigs: state.threatIntelConfigs,
        n8nConfig: state.n8nConfig,
        agentConfig: state.agentConfig,
        networkDiscoveryResult: state.networkDiscoveryResult,
        credentialedConfig: state.credentialedConfig,
        artConsoleOutput: state.artConsoleOutput,
        credentialedHistory: state.credentialedHistory,
        attackVectors: state.attackVectors,
      }),
    }
  )
)
