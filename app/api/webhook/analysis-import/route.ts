import { NextRequest, NextResponse } from 'next/server'

export interface ImportedAnalysisPayload {
  source: 'python_script' | 'discord_bot'
  execution_id?: string
  timestamp: string
  exploit_name: string
  cve_id: string
  remediation_steps: string
  sigma_detection_queries: string
  endpoint_mitigation_commands: string
  metadata?: {
    json_file?: string
    message_id?: string
    channel_id?: string
    target?: string
    attack_type?: string
    os_type?: string
  }
}

export interface FullAnalysisPayload {
  source: 'python_script' | 'discord_bot'
  execution_id?: string
  timestamp: string
  results: ImportedAnalysisPayload[]
  metadata?: Record<string, string>
}

// Parse remediation text into structured RemediationStep objects
function parseRemediationSteps(text: string, phase: 'immediate' | 'short_term' | 'long_term') {
  const steps: any[] = []
  
  // Split by numbered items or bullet points
  const lines = text.split(/\n/).filter(l => l.trim())
  let currentStep: any = null
  
  for (const line of lines) {
    const trimmed = line.trim()
    // Check if this is a new numbered step
    const numberedMatch = trimmed.match(/^(\d+)\.\s*(.+)/)
    const bulletMatch = trimmed.match(/^[-•*]\s*(.+)/)
    
    if (numberedMatch || bulletMatch) {
      if (currentStep) {
        steps.push(currentStep)
      }
      const title = numberedMatch ? numberedMatch[2] : bulletMatch![1]
      currentStep = {
        id: `rem_${phase}_${Date.now()}_${steps.length}`,
        title: title.substring(0, 100),
        description: title,
        command: '',
        target_scope: 'affected_systems',
        expected_outcome: 'Mitigate vulnerability',
        risk_if_skipped: 'System remains vulnerable',
        requires_approval: phase !== 'immediate',
        is_disruptive: phase === 'long_term',
        status: 'pending',
      }
    } else if (currentStep && trimmed) {
      // Append to current step description
      currentStep.description += '\n' + trimmed
      // Check if this line contains a command
      if (trimmed.includes('```') || trimmed.startsWith('$') || trimmed.startsWith('>') || 
          trimmed.includes('powershell') || trimmed.includes('bash') || trimmed.includes('cmd')) {
        currentStep.command = trimmed.replace(/```\w*/g, '').trim()
      }
    }
  }
  
  if (currentStep) {
    steps.push(currentStep)
  }
  
  // If no structured steps found, create one from the whole text
  if (steps.length === 0 && text.trim()) {
    steps.push({
      id: `rem_${phase}_${Date.now()}_0`,
      title: `${phase.replace('_', ' ')} remediation`,
      description: text.trim(),
      command: '',
      target_scope: 'affected_systems',
      expected_outcome: 'Mitigate vulnerability',
      risk_if_skipped: 'System remains vulnerable',
      requires_approval: phase !== 'immediate',
      is_disruptive: phase === 'long_term',
      status: 'pending',
    })
  }
  
  return steps
}

// Parse SIGMA rules text into structured DetectionRule objects
function parseSigmaRules(text: string, cveId: string) {
  const rules: any[] = []
  
  // Try to find YAML blocks or rule definitions
  const yamlBlocks = text.split(/```(?:yaml|yml)?/i)
  let ruleIndex = 0
  
  for (const block of yamlBlocks) {
    const trimmed = block.trim()
    if (!trimmed || trimmed.startsWith('```')) continue
    
    // Check if this looks like a SIGMA rule (has title: or detection:)
    const isSigmaRule = trimmed.includes('title:') || trimmed.includes('detection:') || 
                        trimmed.includes('logsource:') || trimmed.includes('condition:')
    
    // Extract title if present
    const titleMatch = trimmed.match(/title:\s*(.+)/i)
    const title = titleMatch ? titleMatch[1].trim() : `Detection Rule for ${cveId} #${ruleIndex + 1}`
    
    // Extract description if present
    const descMatch = trimmed.match(/description:\s*(.+)/i)
    const description = descMatch ? descMatch[1].trim() : `SIGMA detection rule for ${cveId}`
    
    // Determine severity
    let severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'
    if (trimmed.toLowerCase().includes('critical')) severity = 'critical'
    else if (trimmed.toLowerCase().includes('high')) severity = 'high'
    else if (trimmed.toLowerCase().includes('low')) severity = 'low'
    
    // Extract MITRE references
    const mitreMatches = trimmed.match(/T\d{4}(?:\.\d{3})?/g) || []
    
    if (isSigmaRule || trimmed.length > 50) {
      rules.push({
        id: `rule_${Date.now()}_${ruleIndex}`,
        rule_name: title,
        description: description,
        index: 'logs-*',
        query: trimmed,
        severity: severity,
        mitre: mitreMatches,
        false_positives: 'Review for legitimate administrative activity',
        tuning_notes: 'Adjust thresholds based on environment',
        status: 'draft',
      })
      ruleIndex++
    }
  }
  
  // If no YAML blocks found, try to parse as plain text queries
  if (rules.length === 0 && text.trim()) {
    // Split by common query separators
    const queries = text.split(/\n\n+/).filter(q => q.trim().length > 20)
    
    for (let i = 0; i < queries.length; i++) {
      const query = queries[i].trim()
      const mitreMatches = query.match(/T\d{4}(?:\.\d{3})?/g) || []
      
      rules.push({
        id: `rule_${Date.now()}_${i}`,
        rule_name: `Detection Rule for ${cveId} #${i + 1}`,
        description: `Detection query for ${cveId}`,
        index: 'logs-*',
        query: query,
        severity: 'medium',
        mitre: mitreMatches,
        false_positives: 'Review for legitimate administrative activity',
        tuning_notes: 'Adjust thresholds based on environment',
        status: 'draft',
      })
    }
  }
  
  return rules
}

// Create a full AIAnalysis object from the imported data
function createFullAnalysis(payload: FullAnalysisPayload): any {
  const executionId = payload.execution_id || `import_${Date.now()}`
  const timestamp = payload.timestamp || new Date().toISOString()
  
  // Aggregate all results
  const allRemediation: any[] = []
  const allRules: any[] = []
  const cveAnalyses: any[] = []
  
  for (const result of payload.results) {
    // Parse remediation steps - distribute across phases
    const remSteps = parseRemediationSteps(result.remediation_steps, 'immediate')
    allRemediation.push(...remSteps)
    
    // Parse SIGMA rules
    const sigmaRules = parseSigmaRules(result.sigma_detection_queries, result.cve_id)
    allRules.push(...sigmaRules)
    
    // Add to CVE analysis
    cveAnalyses.push({
      exploit_name: result.exploit_name,
      cve_id: result.cve_id,
      remediation_steps: result.remediation_steps,
      sigma_detection_queries: result.sigma_detection_queries,
      endpoint_mitigation_commands: result.endpoint_mitigation_commands,
    })
  }
  
  // Distribute remediation steps across phases
  const immediate = allRemediation.slice(0, Math.ceil(allRemediation.length / 3))
  const shortTerm = allRemediation.slice(Math.ceil(allRemediation.length / 3), Math.ceil(allRemediation.length * 2 / 3))
  const longTerm = allRemediation.slice(Math.ceil(allRemediation.length * 2 / 3))
  
  // Build the full analysis object
  const analysis = {
    execution_id: executionId,
    attack_summary: {
      overview: `Analysis of ${payload.results.length} exploit(s): ${payload.results.map(r => r.exploit_name).join(', ')}`,
      attacker_objective: 'Exploit identified vulnerabilities',
      skill_level: 'Intermediate to Advanced',
      confidence: 0.85,
    },
    attack_timeline: payload.results.map((r, i) => ({
      timestamp: new Date(Date.now() - (payload.results.length - i) * 60000).toISOString(),
      command: r.exploit_name,
      action: `Exploitation attempt using ${r.exploit_name}`,
      intent: 'Gain unauthorized access or escalate privileges',
      mitre: allRules.flatMap(rule => rule.mitre).slice(0, 3),
      risk: 'high',
    })),
    impact_assessment: {
      blast_radius: payload.results.length > 3 ? 'Wide' : payload.results.length > 1 ? 'Moderate' : 'Limited',
      assets_affected: payload.results.map(r => r.metadata?.target || 'Unknown target'),
      business_risk: 'Potential data breach and system compromise',
      worst_case_scenario: 'Complete system compromise with data exfiltration',
    },
    remediation: {
      immediate: immediate.length > 0 ? immediate : [{
        id: `rem_immediate_${Date.now()}`,
        title: 'Apply security patches',
        description: payload.results.map(r => r.remediation_steps).join('\n\n'),
        command: '',
        target_scope: 'affected_systems',
        expected_outcome: 'Vulnerabilities patched',
        risk_if_skipped: 'Systems remain vulnerable',
        requires_approval: false,
        is_disruptive: false,
        status: 'pending',
      }],
      short_term: shortTerm.length > 0 ? shortTerm : [],
      long_term: longTerm.length > 0 ? longTerm : [],
    },
    detection_rules: allRules.length > 0 ? allRules : [{
      id: `rule_${Date.now()}`,
      rule_name: `Detection for ${payload.results[0]?.cve_id || 'imported exploits'}`,
      description: 'Detection rule from imported analysis',
      index: 'logs-*',
      query: payload.results.map(r => r.sigma_detection_queries).join('\n\n'),
      severity: 'high',
      mitre: [],
      false_positives: 'Review for legitimate activity',
      tuning_notes: 'Adjust based on environment',
      status: 'draft',
    }],
    threat_intelligence: {
      summary: `Threat analysis for CVEs: ${payload.results.map(r => r.cve_id).join(', ')}`,
      ioc_correlation: payload.results.map(r => r.cve_id),
      confidence: 0.8,
    },
    assumptions_and_gaps: [
      'Analysis based on exploit signatures and known CVE data',
      'Actual impact may vary based on environment configuration',
    ],
    overall_confidence: 0.85,
    cve_analysis: cveAnalyses,
  }
  
  return analysis
}

// In-memory store for imported analyses
const importedAnalyses: Map<string, any> = new Map()

export async function POST(request: NextRequest) {
  try {
    const body: FullAnalysisPayload = await request.json()

    if (!body.results || !Array.isArray(body.results) || body.results.length === 0) {
      return NextResponse.json(
        { success: false, error: 'Invalid payload: results array required' },
        { status: 400 }
      )
    }

    const analysis = createFullAnalysis(body)
    importedAnalyses.set(analysis.execution_id, analysis)

    // Keep only last 50 analyses
    if (importedAnalyses.size > 50) {
      const oldestKey = importedAnalyses.keys().next().value
      if (oldestKey) {
        importedAnalyses.delete(oldestKey)
      }
    }

    console.log(`[ANALYSIS IMPORT] Created analysis ${analysis.execution_id} with ${body.results.length} CVE(s)`)

    return NextResponse.json({
      success: true,
      execution_id: analysis.execution_id,
      analysis: analysis,
      message: `Created analysis with ${analysis.remediation.immediate.length + analysis.remediation.short_term.length + analysis.remediation.long_term.length} remediation steps and ${analysis.detection_rules.length} detection rules`,
    })
  } catch (error: any) {
    console.error('[ANALYSIS IMPORT ERROR]', error)
    return NextResponse.json(
      { success: false, error: error.message || 'Failed to import analysis' },
      { status: 500 }
    )
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const executionId = searchParams.get('execution_id')

    if (executionId) {
      const analysis = importedAnalyses.get(executionId)
      if (!analysis) {
        return NextResponse.json(
          { success: false, error: 'Analysis not found' },
          { status: 404 }
        )
      }
      return NextResponse.json({ success: true, analysis })
    }

    // Return all analyses
    const allAnalyses = Array.from(importedAnalyses.values())
    return NextResponse.json({
      success: true,
      count: allAnalyses.length,
      analyses: allAnalyses,
    })
  } catch (error: any) {
    console.error('[ANALYSIS IMPORT GET ERROR]', error)
    return NextResponse.json(
      { success: false, error: error.message || 'Failed to retrieve analyses' },
      { status: 500 }
    )
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  })
}
