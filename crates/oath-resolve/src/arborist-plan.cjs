'use strict'
const { execFileSync } = require('node:child_process')
const { join, relative } = require('node:path')
const { existsSync, readFileSync } = require('node:fs')
const { createRequire } = require('node:module')

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
  const stringOption = (name, fallback) => {
    const value = npmrc[name]
    if (value === undefined) return fallback
    return value.trim().replace(/^(['"])(.*)\1$/, '$2')
  }
  // npm's save-prefix / save-exact decide how added registry packages are
  // written back to package.json.
  const savePrefix = boolOption('save-exact') ? '' : stringOption('save-prefix', '^')
  const arboristRequire = createRequire(require.resolve('@npmcli/arborist/package.json', { paths: [process.env.OATH_ARBORIST_PATH || process.cwd()] }))
  // npm's min-release-age is a relative `before` cutoff handed to pacote, so
  // npm-pick-manifest only considers versions published by then. Excluded
  // packages see no cutoff at all, which is what min-release-age-exclude
  // means: pacote.manifest is wrapped because that is the single call site
  // Arborist uses to pick a version for a dependency edge.
  const before = request.before ? new Date(request.before) : null
  if (before && Number.isNaN(before.getTime())) throw new Error(`invalid before cutoff ${request.before}`)
  const excluded = new Set(Array.isArray(request.min_release_age_exclude) ? request.min_release_age_exclude : [])
  if (before && excluded.size) {
    const pacote = arboristRequire('pacote')
    const npa = arboristRequire('npm-package-arg')
    const originalManifest = pacote.manifest
    pacote.manifest = (spec, opts = {}) => {
      let name = null
      try { name = (typeof spec === 'string' ? npa(spec) : spec).name } catch {}
      if (name && excluded.has(name)) return originalManifest(spec, { ...opts, before: null })
      return originalManifest(spec, opts)
    }
  }
  const arborist = new Arborist({
    path: project,
    audit: false,
    ignoreScripts: true,
    savePrefix,
    ...(before ? { before } : {}),
    legacyPeerDeps: boolOption('legacy-peer-deps'),
    strictPeerDeps: boolOption('strict-peer-deps'),
    // npm 11 defaults install-links to false: local directory dependencies
    // remain links unless the project explicitly opts into packed installs.
    installLinks: boolOption('install-links', false)
  })
  const idealOptions = {}
  if (request.add && request.add.length) idealOptions.add = request.add
  if (request.rm && request.rm.length) idealOptions.rm = request.rm
  if (request.update === true || (Array.isArray(request.update) && request.update.length)) idealOptions.update = request.update
  if (request.save_type) idealOptions.saveType = request.save_type
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
    .map(node => {
      // A link node's own package record can be empty when the tree was
      // loaded from disk; its lifecycle scripts live in the link target.
      const manifest = (node.isLink && node.target && node.target.package) ? node.target.package : node.package
      return ({
      location: node.location.replaceAll('\\', '/'),
      install_name: node.name,
      name: node.package.name,
      version: node.package.version || manifest.version || '0.0.0',
      resolved: node.resolved || null,
      integrity: node.integrity ? String(node.integrity) : null,
      dev: Boolean(node.dev),
      optional: Boolean(node.optional),
      has_install_script: Boolean(manifest.scripts && (
        manifest.scripts.preinstall ||
        manifest.scripts.install ||
        manifest.scripts.postinstall
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
      })
    })
    .sort((a, b) => a.location.localeCompare(b.location))
  const invalid_edges = nodes.flatMap(node => node.edges.filter(edge => !edge.valid).map(edge => ({ location: node.location, ...edge })))
  const wantsManifest = (request.add && request.add.length) || (request.rm && request.rm.length)
  const root_manifest = wantsManifest ? savedRootManifest(arborist, tree, request, savePrefix) : null
  // Each add spec with the name Arborist resolved for it: registry specs carry
  // their own, while git, directory, and tarball specs only learn theirs from
  // the fetched manifest.
  const added = (arborist[Symbol.for('resolvedAdd')] || []).map(spec => ({ raw: spec.raw, name: spec.name }))
  process.stdout.write(JSON.stringify({
    schema_version: 2,
    planner: { name: '@npmcli/arborist', npm: process.env.OATH_NPM_REFERENCE_VERSION || execFileSync('npm', ['--version'], { encoding: 'utf8' }).trim() },
    project,
    nodes,
    removed_locations,
    invalid_edges,
    root_manifest,
    added
  }))
}

// Reproduce the package.json dependency fields npm would write after an add or
// remove request. Arborist already applied the user's add/rm to the in-memory
// root manifest while building the ideal tree; a dry run skips `saveIdealTree`,
// so the spec rewriting (save-prefix ranges, npm: aliases, hosted git
// shortcuts, relative file: paths) and @npmcli/package-json's dependency
// ordering are replayed here from the same sources.
function savedRootManifest (arborist, tree, request, savePrefix) {
  const arboristRequire = createRequire(require.resolve('@npmcli/arborist/package.json', { paths: [process.env.OATH_ARBORIST_PATH || process.cwd()] }))
  const npa = arboristRequire('npm-package-arg')
  const { subset, intersects } = arboristRequire('semver')
  const updateDependencies = arboristRequire('@npmcli/package-json/lib/update-dependencies.js')
  const { saveTypeMap, hasSubKey } = arboristRequire('@npmcli/arborist/lib/add-rm-pkg-deps.js')
  const relpath = (from, to) => relative(from, to).replace(/\\/g, '/')
  // reify() hands back the former ideal tree and clears arborist.idealTree,
  // so the returned tree is the root whose package Arborist edited.
  const root = tree
  const resolvedAdd = arborist[Symbol.for('resolvedAdd')] || []
  for (const spec of resolvedAdd) {
    const addTree = spec.tree
    if (!addTree || addTree !== root) continue
    const name = spec.name
    const edge = addTree.edgesOut.get(name)
    if (!edge) continue
    const pkg = addTree.package
    const req = npa.resolve(name, edge.spec, addTree.realpath)
    const { rawSpec, subSpec } = req
    const rangeSpec = subSpec ? subSpec.rawSpec : rawSpec
    const child = edge.to
    if (!child) continue
    let newSpec
    const isLocalDep = req.type === 'directory' || req.type === 'file'
    if (req.registry) {
      const version = child.version
      const prefixRange = version ? savePrefix + version : '*'
      const isRange = (subSpec || req).type === 'range'
      let range = rangeSpec
      if (!isRange || rangeSpec === '*' || subset(prefixRange, rangeSpec, { loose: true })) {
        range = prefixRange
      }
      const pname = child.packageName
      newSpec = name !== pname ? `npm:${pname}@${range}` : range
    } else if (req.hosted) {
      const h = req.hosted
      const opt = { noCommittish: false }
      newSpec = (h.https && h.auth) ? `git+${h.https(opt)}` : h.shortcut(opt)
    } else if (isLocalDep) {
      if (edge.type === 'workspace') {
        const { version } = edge.to.target
        newSpec = version ? savePrefix + version : '*'
      } else {
        const p = req.fetchSpec.replace(/^file:/, '')
        newSpec = `file:${relpath(addTree.realpath, p)}`
      }
    } else {
      newSpec = req.saveSpec
    }
    if (request.save_type) {
      const depType = saveTypeMap.get(request.save_type)
      pkg[depType] = pkg[depType] || {}
      pkg[depType][name] = newSpec
      if (request.save_type === 'prod' && pkg.optionalDependencies) {
        delete pkg.optionalDependencies[name]
      }
    } else {
      if (hasSubKey(pkg, 'dependencies', name)) pkg.dependencies[name] = newSpec
      if (hasSubKey(pkg, 'devDependencies', name)) {
        pkg.devDependencies[name] = newSpec
        if (hasSubKey(pkg, 'peerDependencies', name) && (isLocalDep || !intersects(newSpec, pkg.peerDependencies[name]))) {
          pkg.peerDependencies[name] = newSpec
        }
        if (hasSubKey(pkg, 'optionalDependencies', name) && (isLocalDep || !intersects(newSpec, pkg.optionalDependencies[name]))) {
          pkg.optionalDependencies[name] = newSpec
        }
      } else {
        if (hasSubKey(pkg, 'peerDependencies', name)) pkg.peerDependencies[name] = newSpec
        if (hasSubKey(pkg, 'optionalDependencies', name)) pkg.optionalDependencies[name] = newSpec
      }
    }
  }
  const pkg = root.package
  const depTypes = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']
  const content = {}
  for (const type of depTypes) if (pkg[type]) content[type] = { ...pkg[type] }
  const updated = updateDependencies({ content, originalContent: pkg })
  const manifest = {}
  for (const type of depTypes) manifest[type] = updated[type] && Object.keys(updated[type]).length ? updated[type] : null
  return manifest
}

main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1 })
