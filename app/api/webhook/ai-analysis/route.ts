import { NextRequest, NextResponse } from 'next/server'

// This endpoint receives AI analysis results from n8n
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    
    const {
      execution_id,
      attack_summary,
      attack_timeline,
      impact_assessment,
      remediation,
      detection_rules,
      threat_intelligence,
      assumptions_and_gaps,
      overall_confidence,
    } = body

    // Log the incoming AI analysis
    console.log(`[AI ANALYSIS] Execution: ${execution_id}`, {
      confidence: overall_confidence,
      rules_count: detection_rules?.length || 0,
      remediation_steps: 
        (remediation?.immediate?.length || 0) + 
        (remediation?.short_term?.length || 0) + 
        (remediation?.long_term?.length || 0),
    })

    // Validate required fields
    if (!execution_id || !attack_summary) {
      return NextResponse.json(
        { success: false, error: 'Missing required fields' },
        { status: 400 }
      )
    }

    // Here you would typically:
    // 1. Store the analysis in a database
    // 2. Trigger WebSocket notification to connected clients
    // 3. Update the platform state

    return NextResponse.json({
      success: true,
      message: 'AI analysis received',
      execution_id,
      processed_at: new Date().toISOString(),
    })
  } catch (error) {
    console.error('[AI ANALYSIS ERROR]', error)
    return NextResponse.json(
      { success: false, error: 'Failed to process AI analysis' },
      { status: 500 }
    )
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  })
}

