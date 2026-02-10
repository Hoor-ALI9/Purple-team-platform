import { NextRequest, NextResponse } from 'next/server'

interface NotificationPayload {
  webhook_url: string
  test?: boolean
  // Attack details
  attack_type?: string          // 'blackbox' | 'credentialed' | 'custom_command' | 'art_test' | 'metasploit'
  status?: 'success' | 'failure'
  execution_id?: string
  target_ip?: string
  target_port?: number
  module?: string               // attack module / technique / command name
  command?: string              // the actual command executed
  output?: string               // raw output (truncated if needed)
  stderr?: string               // stderr if any
  exit_code?: number
  os_type?: string
  executor?: string             // e.g. 'bash', 'powershell', 'msfconsole'
  duration?: string             // execution duration
  timestamp?: string
  extra_fields?: Array<{ name: string; value: string; inline?: boolean }>
}

const MAX_FIELD_LENGTH = 1024
const MAX_DESCRIPTION_LENGTH = 4000

function truncate(text: string, maxLen: number): string {
  if (!text) return ''
  if (text.length <= maxLen) return text
  return text.substring(0, maxLen - 20) + '\n... (truncated)'
}

function buildTestEmbed() {
  return {
    username: 'Purple Team Platform',
    avatar_url: 'https://cdn-icons-png.flaticon.com/512/6941/6941697.png',
    embeds: [
      {
        title: '🧪 Webhook Test — Connection Successful',
        description: 'Your Discord webhook is connected to the Purple Team Platform. You will receive rich notifications here for all attack executions.',
        color: 0x5865F2,  // Discord blurple
        fields: [
          { name: '📡 Status', value: '`CONNECTED`', inline: true },
          { name: '🕐 Timestamp', value: `\`${new Date().toISOString()}\``, inline: true },
        ],
        footer: {
          text: 'Purple Team Platform • Webhook Test',
        },
        timestamp: new Date().toISOString(),
      },
    ],
  }
}

function buildAttackEmbed(payload: NotificationPayload) {
  const isSuccess = payload.status === 'success'
  const color = isSuccess ? 0x22c55e : 0xef4444  // green or red

  const statusEmoji = isSuccess ? '✅' : '❌'
  const statusLabel = isSuccess ? 'SUCCESS' : 'FAILURE'

  // Map attack type to readable label
  const attackTypeLabels: Record<string, string> = {
    blackbox: '🎯 Black Box Attack',
    credentialed: '🔑 Credentialed Attack',
    custom_command: '💻 Custom Command',
    art_test: '⚛️ Atomic Red Team Test',
    metasploit: '🗡️ Metasploit Module',
  }
  const attackLabel = attackTypeLabels[payload.attack_type || ''] || `🔧 ${payload.attack_type || 'Unknown'}`

  // Build description with execution details
  const descParts: string[] = []
  if (payload.command) {
    descParts.push(`**Command Executed:**\n\`\`\`bash\n${truncate(payload.command, 500)}\n\`\`\``)
  }
  if (payload.output) {
    descParts.push(`**Output:**\n\`\`\`\n${truncate(payload.output, 1500)}\n\`\`\``)
  }
  if (payload.stderr) {
    descParts.push(`**Stderr:**\n\`\`\`\n${truncate(payload.stderr, 500)}\n\`\`\``)
  }

  const description = truncate(descParts.join('\n'), MAX_DESCRIPTION_LENGTH)

  // Build fields
  const fields: Array<{ name: string; value: string; inline?: boolean }> = [
    { name: '📋 Attack Type', value: `\`${payload.attack_type?.toUpperCase() || 'N/A'}\``, inline: true },
    { name: `${statusEmoji} Status`, value: `\`${statusLabel}\``, inline: true },
    { name: '🎯 Target', value: `\`${payload.target_ip || 'N/A'}${payload.target_port ? ':' + payload.target_port : ''}\``, inline: true },
  ]

  if (payload.module) {
    fields.push({ name: '📦 Module / Technique', value: `\`\`\`${truncate(payload.module, MAX_FIELD_LENGTH - 10)}\`\`\``, inline: false })
  }

  if (payload.os_type) {
    fields.push({ name: '🖥️ OS Type', value: `\`${payload.os_type}\``, inline: true })
  }

  if (payload.executor) {
    fields.push({ name: '⚙️ Executor', value: `\`${payload.executor}\``, inline: true })
  }

  if (payload.exit_code !== undefined && payload.exit_code !== null) {
    fields.push({ name: '🔢 Exit Code', value: `\`${payload.exit_code}\``, inline: true })
  }

  if (payload.execution_id) {
    fields.push({ name: '🆔 Execution ID', value: `\`${payload.execution_id}\``, inline: true })
  }

  if (payload.duration) {
    fields.push({ name: '⏱️ Duration', value: `\`${payload.duration}\``, inline: true })
  }

  // Add any extra custom fields
  if (payload.extra_fields) {
    for (const f of payload.extra_fields) {
      fields.push({ name: f.name, value: truncate(f.value, MAX_FIELD_LENGTH), inline: f.inline ?? true })
    }
  }

  return {
    username: 'Purple Team Platform',
    avatar_url: 'https://cdn-icons-png.flaticon.com/512/6941/6941697.png',
    embeds: [
      {
        title: `${statusEmoji} ${attackLabel} — ${statusLabel}`,
        description: description || undefined,
        color,
        fields,
        footer: {
          text: `Purple Team Platform • ${payload.attack_type || 'attack'}`,
        },
        timestamp: payload.timestamp || new Date().toISOString(),
      },
    ],
  }
}

/**
 * POST /api/webhook/notification
 * Send a rich embed notification to a Discord webhook
 */
export async function POST(request: NextRequest) {
  try {
    const payload: NotificationPayload = await request.json()
    const { webhook_url, test } = payload

    if (!webhook_url) {
      return NextResponse.json(
        { success: false, error: 'No webhook URL provided' },
        { status: 400 }
      )
    }

    // Validate it looks like a Discord webhook
    if (!webhook_url.startsWith('https://discord.com/api/webhooks/') && !webhook_url.startsWith('https://discordapp.com/api/webhooks/')) {
      return NextResponse.json(
        { success: false, error: 'Invalid Discord webhook URL' },
        { status: 400 }
      )
    }

    const body = test ? buildTestEmbed() : buildAttackEmbed(payload)

    const res = await fetch(webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })

    if (res.ok || res.status === 204) {
      return NextResponse.json({ success: true, message: 'Notification sent' })
    } else {
      const errorText = await res.text()
      console.error('[DISCORD WEBHOOK ERROR]', res.status, errorText)
      return NextResponse.json(
        { success: false, error: `Discord returned ${res.status}: ${errorText}` },
        { status: 502 }
      )
    }
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    console.error('[NOTIFICATION ERROR]', errorMessage)
    return NextResponse.json(
      { success: false, error: errorMessage },
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
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  })
}
