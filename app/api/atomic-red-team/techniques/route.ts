import { NextRequest, NextResponse } from 'next/server'
import fs from 'fs'
import path from 'path'
import yaml from 'js-yaml'

interface AtomicTest {
  name: string
  auto_generated_guid: string
  description: string
  supported_platforms: string[]
  executor: {
    name: string
    command?: string
    steps?: string
    cleanup_command?: string
    elevation_required?: boolean
  }
  input_arguments?: Record<string, {
    description: string
    type: string
    default: string | number
  }>
}

interface TechniqueYaml {
  attack_technique: string
  display_name: string
  atomic_tests: AtomicTest[]
}

interface ParsedTechnique {
  technique_id: string
  display_name: string
  tests: Array<{
    index: number
    name: string
    guid: string
    description: string
    platforms: string[]
    executor_type: string
    command: string
    cleanup_command: string
    elevation_required: boolean
    input_arguments: Record<string, {
      description: string
      type: string
      default: string | number
    }>
  }>
}

// In-memory cache so we don't re-parse every request
let cachedTechniques: ParsedTechnique[] | null = null
let cacheTimestamp = 0
const CACHE_TTL = 300_000 // 5 minutes

function resolveCommand(command: string, args: Record<string, { default: string | number }> | undefined): string {
  if (!command || !args) return command || ''
  let resolved = command
  for (const [key, val] of Object.entries(args)) {
    // Atomic Red Team uses #{var_name} for variable interpolation
    resolved = resolved.replace(new RegExp(`#\\{${key}\\}`, 'g'), String(val.default))
  }
  return resolved
}

function loadTechniques(): ParsedTechnique[] {
  const atomicsDir = path.join(process.cwd(), 'atomic-red-team-master', 'atomics')
  const techniques: ParsedTechnique[] = []

  if (!fs.existsSync(atomicsDir)) {
    console.error('[ART] atomics directory not found:', atomicsDir)
    return []
  }

  const dirs = fs.readdirSync(atomicsDir).filter(d => /^T\d+/.test(d))

  for (const dir of dirs) {
    const yamlPath = path.join(atomicsDir, dir, `${dir}.yaml`)
    if (!fs.existsSync(yamlPath)) continue

    try {
      const content = fs.readFileSync(yamlPath, 'utf-8')
      const parsed = yaml.load(content) as TechniqueYaml
      if (!parsed || !parsed.atomic_tests) continue

      const tests = parsed.atomic_tests.map((test, idx) => {
        const command = test.executor?.command || test.executor?.steps || ''
        const cleanupCommand = test.executor?.cleanup_command || ''

        return {
          index: idx + 1,
          name: test.name,
          guid: test.auto_generated_guid || '',
          description: (test.description || '').trim().substring(0, 500),
          platforms: test.supported_platforms || [],
          executor_type: test.executor?.name || 'unknown',
          command: resolveCommand(command, test.input_arguments),
          cleanup_command: resolveCommand(cleanupCommand, test.input_arguments),
          elevation_required: test.executor?.elevation_required || false,
          input_arguments: test.input_arguments || {},
        }
      })

      techniques.push({
        technique_id: parsed.attack_technique,
        display_name: parsed.display_name,
        tests,
      })
    } catch (err) {
      // Skip malformed YAML files silently
      console.warn(`[ART] Failed to parse ${yamlPath}:`, err)
    }
  }

  // Sort by technique ID
  techniques.sort((a, b) => a.technique_id.localeCompare(b.technique_id, undefined, { numeric: true }))
  return techniques
}

/**
 * GET /api/atomic-red-team/techniques
 * Query params:
 *   - platform: "linux" | "windows" | "macos" (optional, filters tests by platform)
 *   - search: string (optional, filters by technique_id or display_name)
 *   - technique_id: string (optional, return single technique details)
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const platform = searchParams.get('platform')
    const search = searchParams.get('search')?.toLowerCase()
    const techniqueId = searchParams.get('technique_id')

    // Load from cache or parse fresh
    const now = Date.now()
    if (!cachedTechniques || now - cacheTimestamp > CACHE_TTL) {
      cachedTechniques = loadTechniques()
      cacheTimestamp = now
    }

    let results = cachedTechniques

    // Filter by specific technique ID
    if (techniqueId) {
      results = results.filter(t => t.technique_id.toUpperCase() === techniqueId.toUpperCase())
      if (results.length === 0) {
        return NextResponse.json({ success: false, error: 'Technique not found' }, { status: 404 })
      }
      // For single technique, return full details including commands
      return NextResponse.json({
        success: true,
        technique: results[0],
      })
    }

    // Filter by platform
    if (platform) {
      results = results
        .map(t => ({
          ...t,
          tests: t.tests.filter(test => test.platforms.includes(platform)),
        }))
        .filter(t => t.tests.length > 0)
    }

    // Filter by search text
    if (search) {
      results = results.filter(t =>
        t.technique_id.toLowerCase().includes(search) ||
        t.display_name.toLowerCase().includes(search) ||
        t.tests.some(test => test.name.toLowerCase().includes(search))
      )
    }

    // Return lightweight list (no commands for list view — saves bandwidth)
    const lightweight = results.map(t => ({
      technique_id: t.technique_id,
      display_name: t.display_name,
      test_count: t.tests.length,
      platforms: Array.from(new Set(t.tests.flatMap(test => test.platforms))),
      tests: t.tests.map(test => ({
        index: test.index,
        name: test.name,
        guid: test.guid,
        description: test.description,
        platforms: test.platforms,
        executor_type: test.executor_type,
        elevation_required: test.elevation_required,
      })),
    }))

    return NextResponse.json({
      success: true,
      total: lightweight.length,
      techniques: lightweight,
    })
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    console.error('[ART API ERROR]', message)
    return NextResponse.json({ success: false, error: message }, { status: 500 })
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  })
}

