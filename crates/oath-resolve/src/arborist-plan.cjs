'use strict'
const { execFileSync } = require('node:child_process')
const { join } = require('node:path')
const { existsSync, readFileSync } = require('node:fs')

function loadNpmModule (name, override) {
  if (override && process.env[override]) return require(process.env[override])
  try { return require(name) } catch {}
  const root = execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim()
  return require(join(root, 'npm', 'node_modules', ...name.split('/')))
}

async function main () {
  const project = process.argv[2]
  if (!project) throw new Error('project path is required')
  const request = process.argv[3] ? JSON.parse(process.argv[3]) : {}
  const Arborist = loadNpmModule('@npmcli/arborist', 'OATH_ARBORIST_PATH')
  const npmrc = {}
  const npmrcPath = join(project, '.npmrc')
  if (existsSync(npmrcPath)) {
    for (const raw of readFileSync(npmrcPath, 'utf8').split(/\r?\n/)) {
      const line = raw.trim()
      if (!line || line.startsWith('#') || !line.includes('=')) continue
      const [key, ...rest] = line.split('=')
      npmrc[key.trim()] = rest.join('=').trim()
    }
  }
  const boolOption = (name, fallback = false) => {
    const value = npmrc[name]
    if (value === undefined) return fallback
    const normalized = value.trim().replace(/^(['"])(.*)\1$/, '$2').toLowerCase()
    return normalized === 'true'
  }
  const arborist = new Arborist({
    path: project,
    audit: false,
    ignoreScripts: true,
    legacyPeerDeps: boolOption('legacy-peer-deps'),
    strictPeerDeps: boolOption('strict-peer-deps'),
    preferDedupe: Boolean(request.prefer_dedupe) || boolOption('prefer-dedupe'),
    // npm 11 defaults install-links to false: local directory dependencies
    // remain links unless the project explicitly opts into packed installs.
    installLinks: boolOption('install-links', false)
  })
  const idealOptions = {}
  if (request.add && request.add.length) idealOptions.add = request.add
  if (request.rm && request.rm.length) idealOptions.rm = request.rm
  if (request.update === true || (Array.isArray(request.update) && request.update.length)) idealOptions.update = request.update
  if (request.save_type) idealOptions.saveType = request.save_type
  if (Array.isArray(request.workspaces) && request.workspaces.length) idealOptions.workspaces = request.workspaces
  // Compute npm's final platform, optional, peer, and pruning decisions without
  // writing package contents. Oath remains the only materialization authority.
  const tree = await arborist.reify({ ...idealOptions, dryRun: true, ignoreScripts: true })
  const unchangedLocations = new Set((arborist.diff && arborist.diff.unchanged ? arborist.diff.unchanged : [])
    .map(node => node.location.replaceAll('\\', '/')))
  const removed_locations = (arborist.diff && arborist.diff.removed ? arborist.diff.removed : [])
    .map(node => node.location.replaceAll('\\', '/'))
    .filter(location => location.startsWith('node_modules/'))
    .sort((a, b) => a.localeCompare(b))
  const nodes = [...tree.inventory.values()]
    // Arborist inventory also contains workspace source nodes (for example
    // packages/tool). Oath materializes only install-tree locations; workspace
    // sources remain validated targets of their node_modules link nodes.
    // Dependencies bundled by an installed registry package are already
    // present inside that package's verified tarball. Root package bundle
    // declarations are different: npm still installs those dependencies from
    // the registry because the project root itself is not a tarball. Arborist's
    // inDepBundle predicate captures exactly that distinction; inBundle also
    // includes dependencies bundled only by the project root.
    .filter(node => !node.inDepBundle && node.location && node.location.replaceAll('\\', '/').startsWith('node_modules/') && node.package && node.package.name && (node.isLink || node.package.version))
    .map(node => ({
      location: node.location.replaceAll('\\', '/'),
      install_name: node.name,
      name: node.package.name,
      version: node.package.version || '0.0.0',
      resolved: node.resolved || null,
      integrity: node.integrity ? String(node.integrity) : null,
      dev: Boolean(node.dev),
      optional: Boolean(node.optional),
      peer: Boolean(node.peer),
      has_install_script: Boolean(node.package.scripts && (
        node.package.scripts.preinstall ||
        node.package.scripts.install ||
        node.package.scripts.postinstall
      )),
      reuse_existing: unchangedLocations.has(node.location.replaceAll('\\', '/')),
      link: Boolean(node.isLink),
      target: node.isLink && node.target ? node.target.path : null,
      edges: [...node.edgesOut.values()].map(edge => ({
        name: edge.name,
        spec: edge.spec,
        type: edge.type,
        target_location: edge.to ? edge.to.location.replaceAll('\\', '/') : null,
        valid: Boolean(edge.valid)
      })).sort((a, b) => a.name.localeCompare(b.name))
    }))
    .sort((a, b) => a.location.localeCompare(b.location))
  const invalid_edges = nodes.flatMap(node => node.edges.filter(edge => !edge.valid).map(edge => ({ location: node.location, ...edge })))
  process.stdout.write(JSON.stringify({
    schema_version: 2,
    planner: { name: '@npmcli/arborist', npm: process.env.OATH_NPM_REFERENCE_VERSION || execFileSync('npm', ['--version'], { encoding: 'utf8' }).trim() },
    project,
    nodes,
    removed_locations,
    invalid_edges
  }))
}

main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1 })
