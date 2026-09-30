'use strict'

async function main () {
  const project = process.argv[2]
  const selector = process.argv[3]
  if (!project || !selector) throw new Error('project path and selector are required')
  const Arborist = require(process.env.OATH_ARBORIST_PATH)
  const arborist = new Arborist({ path: project, forceActual: true, audit: false })
  const tree = await arborist.loadActual()
  const matches = await tree.querySelectorAll(selector)
  const seen = new Set()
  const result = []
  for (const match of matches) {
    const node = match.target
    if (node.location && seen.has(node.location)) continue
    if (node.location) seen.add(node.location)
    const from = [...node.edgesIn].map(edge => edge.from.location)
    const to = [...node.edgesOut.values()].filter(edge => edge.to).map(edge => edge.to.location)
    result.push({
      ...node.package,
      pkgid: node.pkgid,
      location: node.location,
      path: node.path,
      realpath: node.realpath,
      resolved: node.resolved,
      from,
      to,
      dev: Boolean(node.dev),
      inBundle: Boolean(node.inBundle),
      deduped: from.length > 1,
      overridden: Boolean(match.overridden),
      queryContext: match.queryContext
    })
  }
  process.stdout.write(JSON.stringify(result))
}

main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1 })
