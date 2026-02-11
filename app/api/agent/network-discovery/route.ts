import { NextRequest, NextResponse } from 'next/server'
import { Client } from 'ssh2'

interface AgentSSHConfig {
  ssh_host: string
  ssh_port: number
  ssh_user: string
  ssh_password: string
  agent_path: string
  python_path: string
  network_range?: string
  timing?: string
}

/**
 * Execute a command on the remote agent via SSH and collect stdout
 */
function executeRemoteCommand(config: AgentSSHConfig, command: string, timeoutMs: number = 600000): Promise<string> {
  return new Promise((resolve, reject) => {
    const conn = new Client()
    let stdout = ''
    let stderr = ''
    let resolved = false

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true
        conn.end()
        const timeoutMinutes = Math.round(timeoutMs / 60000)
        reject(new Error(`SSH command timed out after ${timeoutMinutes} minutes. The discovery process may still be running on the agent. Try increasing the timeout or using a faster timing template (T5).`))
      }
    }, timeoutMs)

    conn.on('ready', () => {
      console.log(`[AGENT SSH] Connected to ${config.ssh_host}`)

      conn.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timer)
          if (!resolved) {
            resolved = true
            conn.end()
            reject(err)
          }
          return
        }

        stream.on('close', (code: number) => {
          clearTimeout(timer)
          if (resolved) return
          resolved = true
          conn.end()

          if (code !== 0 && !stdout.trim()) {
            reject(new Error(`Agent command exited with code ${code}: ${stderr || 'No output from agent'}`))
          } else {
            resolve(stdout)
          }
        })

        stream.on('data', (data: Buffer) => {
          stdout += data.toString()
        })

        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString()
          console.log(`[AGENT STDERR] ${data.toString().trim()}`)
        })
      })
    })

    conn.on('error', (err) => {
      clearTimeout(timer)
      if (!resolved) {
        resolved = true
        reject(new Error(`SSH connection failed: ${err.message}`))
      }
    })

    conn.connect({
      host: config.ssh_host,
      port: config.ssh_port || 22,
      username: config.ssh_user,
      password: config.ssh_password,
      readyTimeout: 15000,
      algorithms: {
        serverHostKey: ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512']
      }
    })
  })
}

/**
 * POST /api/agent/network-discovery
 * Connects to the Kali agent via SSH and runs network discovery
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const {
      ssh_host,
      ssh_port = 22,
      ssh_user,
      ssh_password,
      agent_path,
      python_path = 'python3',
      network_range,
      timing = 'T4',
    } = body as AgentSSHConfig

    // Validate
    if (!ssh_host || !ssh_user || !ssh_password) {
      return NextResponse.json(
        { success: false, error: 'Missing agent SSH credentials. Configure them in Settings → Agent Configuration.' },
        { status: 400 }
      )
    }

    if (!agent_path) {
      return NextResponse.json(
        { success: false, error: 'Agent path is not configured. Set it in Settings → Agent Configuration.' },
        { status: 400 }
      )
    }

    console.log(`[NETWORK DISCOVERY] Agent ${ssh_host}:${ssh_port} | timing: ${timing} | range: ${network_range || 'auto-detect'}`)

    // Adjust timeout based on timing template (increased for optimized but still thorough scans)
    const timingTimeouts: Record<string, number> = {
      'T1': 2400000, // 40 min for sneaky (very thorough)
      'T2': 1800000, // 30 min for polite
      'T3': 1200000, // 20 min for normal
      'T4': 900000,  // 15 min for aggressive (optimized: was 10 min, now 15 min for safety)
      'T5': 600000,  // 10 min for insane (optimized: was 5 min, now 10 min)
    }
    const timeout = timingTimeouts[timing] || 900000
    const timeoutMinutes = Math.round(timeout / 60000)

    // Build command with timing flag
    const rangeArg = network_range ? ` --range ${network_range}` : ''
    const timingArg = timing ? ` --timing ${timing}` : ''
    const command = `${python_path} "${agent_path}" network-discovery${rangeArg}${timingArg}`

    console.log(`[NETWORK DISCOVERY] Running: ${command}`)
    console.log(`[NETWORK DISCOVERY] Timeout: ${timeoutMinutes} minutes`)

    const rawOutput = await executeRemoteCommand(
      { ssh_host, ssh_port, ssh_user, ssh_password, agent_path, python_path },
      command,
      timeout
    )

    // Parse JSON output
    let result
    try {
      result = JSON.parse(rawOutput.trim())
    } catch {
      const jsonMatch = rawOutput.match(/\{[\s\S]*\}/)
      if (jsonMatch) {
        result = JSON.parse(jsonMatch[0])
      } else {
        throw new Error('Agent did not return valid JSON output')
      }
    }

    console.log(`[NETWORK DISCOVERY] Complete. ${result.summary?.total_hosts || 0} hosts, ${result.summary?.total_suggested_exploits || 0} exploit suggestions.`)

    return NextResponse.json(result)
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    console.error('[NETWORK DISCOVERY ERROR]', errorMessage)

    return NextResponse.json(
      { success: false, error: errorMessage, timestamp: new Date().toISOString() },
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
