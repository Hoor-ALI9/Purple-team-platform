import { NextRequest, NextResponse } from 'next/server'
import { Client } from 'ssh2'

/**
 * POST /api/agent/test-connection
 * Tests SSH connectivity to the Kali agent and runs the status command
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { ssh_host, ssh_port = 22, ssh_user, ssh_password, agent_path, python_path = 'python3' } = body

    if (!ssh_host || !ssh_user || !ssh_password) {
      return NextResponse.json(
        { success: false, error: 'Missing SSH credentials' },
        { status: 400 }
      )
    }

    if (!agent_path) {
      return NextResponse.json(
        { success: false, error: 'Missing agent_path. Please configure the agent script path in settings.' },
        { status: 400 }
      )
    }

    const result = await new Promise<{ success: boolean; agent_version?: string; error?: string; details?: unknown }>((resolve) => {
      const conn = new Client()
      let resolved = false
      
      // Increased timeout to 60s since status command checks multiple tools
      const connectionTimer = setTimeout(() => {
        if (!resolved) {
          resolved = true
          conn.end()
          resolve({ success: false, error: 'SSH connection timed out (15s)' })
        }
      }, 15000)

      const commandTimer = setTimeout(() => {
        if (!resolved) {
          resolved = true
          conn.end()
          resolve({ success: false, error: 'Command execution timed out (60s)' })
        }
      }, 60000)

      const cleanup = () => {
        clearTimeout(connectionTimer)
        clearTimeout(commandTimer)
      }

      conn.on('ready', () => {
        console.log(`[AGENT TEST] Connected to ${ssh_host}`)
        clearTimeout(connectionTimer)

        // Run agent status command - path is already provided, just quote it
        const command = `${python_path} "${agent_path}" status`
        console.log(`[AGENT TEST] Executing: ${command}`)
        
        conn.exec(command, (err, stream) => {
          if (err) {
            cleanup()
            if (!resolved) {
              resolved = true
              conn.end()
              resolve({ success: false, error: `Failed to execute command: ${err.message}` })
            }
            return
          }

          let stdout = ''
          let stderr = ''

          stream.on('close', (code: number) => {
            cleanup()
            if (resolved) return
            resolved = true
            conn.end()

            console.log(`[AGENT TEST] Command exited with code ${code}`)
            console.log(`[AGENT TEST] stdout: ${stdout.substring(0, 500)}`)
            if (stderr) console.log(`[AGENT TEST] stderr: ${stderr.substring(0, 500)}`)

            if (code !== 0 && !stdout.trim()) {
              resolve({
                success: false,
                error: `Agent returned exit code ${code}`,
                details: stderr.trim() || 'No output from agent'
              })
              return
            }

            try {
              const parsed = JSON.parse(stdout.trim())
              resolve({
                success: true,
                agent_version: parsed.agent_version || parsed.agent_info?.agent_version,
                details: parsed
              })
            } catch (parseError) {
              // If status command fails but SSH works, that's still partial success
              console.log(`[AGENT TEST] Failed to parse JSON: ${parseError}`)
              resolve({
                success: true,
                error: 'SSH connected but agent script output is not valid JSON. Check agent_path and script execution.',
                details: { 
                  stdout: stdout.trim().substring(0, 1000), 
                  stderr: stderr.trim().substring(0, 1000),
                  exitCode: code
                }
              })
            }
          })

          stream.on('data', (data: Buffer) => {
            stdout += data.toString()
          })

          stream.stderr.on('data', (data: Buffer) => {
            stderr += data.toString()
            console.log(`[AGENT TEST STDERR] ${data.toString().trim()}`)
          })
        })
      })

      conn.on('error', (err) => {
        cleanup()
        if (!resolved) {
          resolved = true
          console.log(`[AGENT TEST] SSH error: ${err.message}`)
          resolve({ success: false, error: `SSH connection failed: ${err.message}` })
        }
      })

      conn.connect({
        host: ssh_host,
        port: ssh_port || 22,
        username: ssh_user,
        password: ssh_password,
        readyTimeout: 15000,
        algorithms: {
          serverHostKey: ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512']
        }
      })
    })

    return NextResponse.json(result)
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
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

