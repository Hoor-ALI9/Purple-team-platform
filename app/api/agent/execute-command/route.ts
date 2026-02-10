import { NextRequest, NextResponse } from 'next/server'
import { Client } from 'ssh2'

interface ExecuteCommandBody {
  ssh_host: string
  ssh_port: number
  ssh_user: string
  ssh_password: string
  command: string
  timeout?: number    // ms, default 120000
  is_msf?: boolean    // if true, wrap commands in msfconsole RC file
  msf_commands?: string[]  // individual MSF commands to queue
}

/**
 * Execute a raw shell command on the agent via SSH
 */
function sshExec(
  host: string, port: number, user: string, password: string,
  command: string, timeoutMs: number = 120000
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const conn = new Client()
    let stdout = ''
    let stderr = ''

    const timer = setTimeout(() => {
      conn.end()
      reject(new Error(`Command timed out after ${Math.round(timeoutMs / 1000)}s`))
    }, timeoutMs)

    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timer)
          conn.end()
          reject(err)
          return
        }

        stream.on('close', (code: number) => {
          clearTimeout(timer)
          conn.end()
          resolve({ stdout, stderr, exitCode: code })
        })

        stream.on('data', (data: Buffer) => {
          stdout += data.toString()
        })

        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString()
        })
      })
    })

    conn.on('error', (err) => {
      clearTimeout(timer)
      reject(new Error(`SSH connection failed: ${err.message}`))
    })

    conn.connect({
      host,
      port: port || 22,
      username: user,
      password,
      readyTimeout: 15000,
      algorithms: {
        serverHostKey: ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512']
      }
    })
  })
}

/**
 * POST /api/agent/execute-command
 * Execute arbitrary command or Metasploit RC script on the agent
 */
export async function POST(request: NextRequest) {
  try {
    const body: ExecuteCommandBody = await request.json()
    const {
      ssh_host,
      ssh_port = 22,
      ssh_user,
      ssh_password,
      command,
      timeout = 120000,
      is_msf = false,
      msf_commands = [],
    } = body

    if (!ssh_host || !ssh_user || !ssh_password) {
      return NextResponse.json(
        { success: false, error: 'Missing agent SSH credentials.' },
        { status: 400 }
      )
    }

    if (!command && msf_commands.length === 0) {
      return NextResponse.json(
        { success: false, error: 'No command provided.' },
        { status: 400 }
      )
    }

    let finalCommand = command
    let rcFile = ''

    // If Metasploit mode, build RC file from commands
    if (is_msf && msf_commands.length > 0) {
      const ts = Date.now()
      rcFile = `/tmp/msf_manual_${ts}.rc`
      const outputFile = `/tmp/msf_output_${ts}.txt`

      // Build RC content from command list - properly escape for shell
      // Use base64 encoding to avoid quote/special character issues
      const rcContent = msf_commands.join('\n') + '\nexit -y\n'
      const rcContentBase64 = Buffer.from(rcContent).toString('base64')

      // Create RC, run msfconsole, capture output, then cat the output
      // Optimized timeout - reduced minimum from 5 minutes to 2 minutes for faster execution
      const timeoutSeconds = Math.max(120, Math.ceil(timeout / 1000)) // At least 2 minutes (was 5)
      finalCommand = [
        `echo '${rcContentBase64}' | base64 -d > ${rcFile}`,
        `chmod 644 ${rcFile} 2>/dev/null || true`,
        `timeout ${timeoutSeconds} msfconsole -q -r ${rcFile} -o ${outputFile} 2>&1 || echo "[WARNING] msfconsole exited with error or timeout"`,
        `sleep 0.5`,  // Reduced from 2s to 0.5s
        `if [ -f ${outputFile} ]; then cat ${outputFile}; else echo "[ERROR] Output file ${outputFile} was not created. RC file exists: $(test -f ${rcFile} && echo 'yes' || echo 'no')"; fi`,
        `rm -f ${rcFile} ${outputFile} 2>/dev/null || true`,
      ].join(' && ')
    }

    console.log(`[EXECUTE CMD] Host: ${ssh_host} | MSF: ${is_msf} | cmd: ${finalCommand.substring(0, 200)}...`)

    const result = await sshExec(ssh_host, ssh_port, ssh_user, ssh_password, finalCommand, timeout)

    return NextResponse.json({
      success: true,
      output: result.stdout,
      stderr: result.stderr,
      exit_code: result.exitCode,
      timestamp: new Date().toISOString(),
    })
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    console.error('[EXECUTE CMD ERROR]', errorMessage)

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

