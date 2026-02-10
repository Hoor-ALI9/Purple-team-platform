import { NextRequest, NextResponse } from 'next/server'

// This endpoint receives attack results from n8n after Discord trigger
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    
    const {
      execution_id,
      attack_type,
      target_ip,
      target_port,
      raw_output,
      success,
      session_id,
      os_type,
      timestamp,
    } = body

    // Log the incoming attack result
    console.log(`[ATTACK RESULT] Execution: ${execution_id}`, {
      attack_type,
      target_ip,
      success,
      timestamp,
    })

    // Here you would typically:
    // 1. Store the result in a database
    // 2. Trigger WebSocket notification to connected clients
    // 3. Queue the result for AI analysis

    // For now, we'll just return success
    return NextResponse.json({
      success: true,
      message: 'Attack result received',
      execution_id,
      processed_at: new Date().toISOString(),
    })
  } catch (error) {
    console.error('[ATTACK RESULT ERROR]', error)
    return NextResponse.json(
      { success: false, error: 'Failed to process attack result' },
      { status: 500 }
    )
  }
}

// Allow CORS for n8n
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

