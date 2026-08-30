import type { Device, NetworkNode, NetworkSegment, Relation } from './models'
import { topologyEntityKey } from './frontend-utils'

export type TopologyKind = 'segment' | 'node' | 'device'
export type TopologyStatus = 'online' | 'offline' | 'degraded' | 'unknown' | 'configured'
export type TopologyConfidence = 'manual' | 'observed' | 'inferred'
export type TopologyDirection = 'RIGHT' | 'DOWN'
export type TopologyLinkState = 'all' | 'linked' | 'unlinked'

export type TopologyEntity = {
  id: string
  entityId: string
  entityKind: Relation['sourceKind']
  kind: TopologyKind
  label: string
  subtitle: string
  detail: string
  status: TopologyStatus
  connectionCount: number
  searchText: string
  raw: Device | NetworkNode | NetworkSegment
}

export type TopologyLink = {
  id: string
  source: string
  target: string
  label: string
  confidence: TopologyConfidence
  raw: Relation
}

export type TopologyModel = {
  entities: TopologyEntity[]
  links: TopologyLink[]
}

export type TopologyFilters = {
  query: string
  kinds: ReadonlySet<TopologyKind>
  statuses: ReadonlySet<TopologyStatus>
  confidences: ReadonlySet<TopologyConfidence>
  linkState: TopologyLinkState
}

export const allTopologyKinds: TopologyKind[] = ['segment', 'node', 'device']
export const allTopologyStatuses: TopologyStatus[] = ['online', 'degraded', 'offline', 'unknown', 'configured']
export const allTopologyConfidences: TopologyConfidence[] = ['manual', 'observed', 'inferred']

function normalizeStatus(status: string): TopologyStatus {
  const normalized = status.trim().toLowerCase()
  if (normalized === 'online' || normalized === 'offline' || normalized === 'degraded') {
    return normalized
  }
  return 'unknown'
}

export function normalizeConfidence(confidence: string): TopologyConfidence {
  const normalized = confidence.trim().toLowerCase()
  if (normalized === 'manual') {
    return 'manual'
  }
  if (normalized === 'observed' || normalized === 'confirmed') {
    return 'observed'
  }
  return 'inferred'
}

function searchable(parts: Array<string | string[] | Record<string, string> | undefined>) {
  return parts.flatMap((part) => {
    if (Array.isArray(part)) {
      return part
    }
    if (part && typeof part === 'object') {
      return Object.entries(part).flat()
    }
    return part ?? ''
  }).join(' ').toLocaleLowerCase()
}

export function buildTopologyModel(
  devices: Device[],
  networkNodes: NetworkNode[],
  networkSegments: NetworkSegment[],
  relations: Relation[],
): TopologyModel {
  const entities: TopologyEntity[] = [
    ...networkSegments.map((segment): TopologyEntity => ({
      id: topologyEntityKey('networkSegment', segment.id),
      entityId: segment.id,
      entityKind: 'networkSegment',
      kind: 'segment',
      label: segment.name,
      subtitle: segment.cidr || segment.segmentType || 'Network segment',
      detail: segment.gatewayIp || segment.dnsDomain || 'Configured segment',
      status: 'configured',
      connectionCount: 0,
      searchText: searchable([segment.name, segment.cidr, segment.segmentType, segment.gatewayIp, segment.dnsDomain, segment.metadata]),
      raw: segment,
    })),
    ...networkNodes.map((node): TopologyEntity => ({
      id: topologyEntityKey('networkNode', node.id),
      entityId: node.id,
      entityKind: 'networkNode',
      kind: 'node',
      label: node.name,
      subtitle: node.managementIp || node.nodeType || 'Network node',
      detail: [node.vendor, node.model].filter(Boolean).join(' ') || node.nodeType || 'Infrastructure',
      status: normalizeStatus(node.status),
      connectionCount: 0,
      searchText: searchable([node.name, node.managementIp, node.macAddress, node.nodeType, node.vendor, node.model, node.tags, node.metadata]),
      raw: node,
    })),
    ...devices.map((device): TopologyEntity => ({
      id: topologyEntityKey('device', device.id),
      entityId: device.id,
      entityKind: 'device',
      kind: 'device',
      label: device.name,
      subtitle: device.ipAddress || device.hostname || 'Managed device',
      detail: device.role || device.deviceType || 'Endpoint',
      status: normalizeStatus(device.status),
      connectionCount: 0,
      searchText: searchable([device.name, device.hostname, device.ipAddress, device.macAddress, device.role, device.deviceType, device.tags, device.metadata]),
      raw: device,
    })),
  ]

  const entityById = new Map(entities.map((entity) => [entity.id, entity]))
  const links: TopologyLink[] = []
  relations.forEach((relation) => {
    const source = topologyEntityKey(relation.sourceKind, relation.sourceId)
    const target = topologyEntityKey(relation.targetKind, relation.targetId)
    const sourceEntity = entityById.get(source)
    const targetEntity = entityById.get(target)
    if (!sourceEntity || !targetEntity) {
      return
    }
    sourceEntity.connectionCount += 1
    targetEntity.connectionCount += 1
    links.push({
      id: relation.id,
      source,
      target,
      label: relation.relationType.replace(/_/g, ' '),
      confidence: normalizeConfidence(relation.confidence),
      raw: relation,
    })
  })

  return { entities, links }
}

export function entityMatchesFilters(entity: TopologyEntity, filters: TopologyFilters) {
  const query = filters.query.trim().toLocaleLowerCase()
  return filters.kinds.has(entity.kind)
    && filters.statuses.has(entity.status)
    && (filters.linkState === 'all'
      || (filters.linkState === 'linked' && entity.connectionCount > 0)
      || (filters.linkState === 'unlinked' && entity.connectionCount === 0))
    && (!query || entity.searchText.includes(query))
}

export function visibleTopologyIds(model: TopologyModel, filters: TopologyFilters) {
  const entityIds = new Set(model.entities.filter((entity) => entityMatchesFilters(entity, filters)).map((entity) => entity.id))
  const linkIds = new Set(model.links.filter((link) => (
    entityIds.has(link.source)
    && entityIds.has(link.target)
    && filters.confidences.has(link.confidence)
  )).map((link) => link.id))
  return { entityIds, linkIds }
}

export function connectedTopologyIds(model: TopologyModel, selectedId: string | null) {
  const entityIds = new Set<string>()
  const linkIds = new Set<string>()
  if (!selectedId) {
    return { entityIds, linkIds }
  }
  entityIds.add(selectedId)
  model.links.forEach((link) => {
    if (link.source === selectedId || link.target === selectedId) {
      entityIds.add(link.source)
      entityIds.add(link.target)
      linkIds.add(link.id)
    }
  })
  return { entityIds, linkIds }
}

export function fallbackTopologyPositions(entityIds: string[], direction: TopologyDirection) {
  const columns = Math.max(1, Math.ceil(Math.sqrt(entityIds.length)))
  return new Map(entityIds.map((id, index) => {
    const primary = Math.floor(index / columns)
    const secondary = index % columns
    const x = direction === 'RIGHT' ? primary * 320 : secondary * 300
    const y = direction === 'RIGHT' ? secondary * 150 : primary * 170
    return [id, { x, y }]
  }))
}

export function scalableTopologyPositions(entities: Array<Pick<TopologyEntity, 'id' | 'kind'>>, direction: TopologyDirection) {
  const positions = new Map<string, { x: number; y: number }>()
  let groupOffset = 0
  allTopologyKinds.forEach((kind) => {
    const group = entities.filter((entity) => entity.kind === kind)
    const columns = Math.max(1, Math.ceil(Math.sqrt(group.length)))
    const rows = Math.max(1, Math.ceil(group.length / columns))
    group.forEach((entity, index) => {
      const column = index % columns
      const row = Math.floor(index / columns)
      positions.set(entity.id, direction === 'RIGHT'
        ? { x: groupOffset + column * 300, y: row * 150 }
        : { x: column * 300, y: groupOffset + row * 150 })
    })
    groupOffset += (direction === 'RIGHT' ? columns * 300 : rows * 150) + 180
  })
  return positions
}
