import type { Device, NetworkNode, NetworkSegment, Relation } from './models'
import { topologyEntityKey } from './frontend-utils'

export type TopologyKind = 'segment' | 'node' | 'device'
export type TopologyStatus = 'online' | 'offline' | 'degraded' | 'unknown' | 'configured'
export type TopologyConfidence = 'manual' | 'observed' | 'inferred'
export type TopologyLayer = 'physical' | 'logical' | 'reachability' | 'unknown'
export type TopologyLinkKind = 'physical' | 'gateway' | 'membership' | 'management' | 'logical' | 'reachability' | 'unknown'
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
  layer: TopologyLayer
  kind: TopologyLinkKind
  evidence: {
    source: string
    detail: string
    automatic: boolean
    observedAt?: string
  }
  raw?: Relation
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
  layers: ReadonlySet<TopologyLayer>
  linkState: TopologyLinkState
}

export const allTopologyKinds: TopologyKind[] = ['segment', 'node', 'device']
export const allTopologyStatuses: TopologyStatus[] = ['online', 'degraded', 'offline', 'unknown', 'configured']
export const allTopologyConfidences: TopologyConfidence[] = ['manual', 'observed', 'inferred']
export const allTopologyLayers: TopologyLayer[] = ['physical', 'logical', 'reachability', 'unknown']

const physicalRelationTypes = new Set([
  'attached_to',
  'connected_to',
  'ethernet',
  'ethernet_link',
  'lldp_neighbor',
  'switch_port',
  'uplink',
  'uplink_to',
  'wifi_association',
  'wireless_association',
])
const membershipRelationTypes = new Set(['belongs_to', 'member_of_segment', 'on_segment', 'on_vlan'])
const gatewayRelationTypes = new Set(['gateway_for', 'routed_by', 'routes_for'])
const logicalRelationTypes = new Set(['bridged_to', 'bridges', 'nat_for', 'tunnel', 'tunnel_to', 'vpn', 'vpn_peer'])
const reachabilityRelationTypes = new Set(['blocked_from', 'blocked_to', 'can_reach', 'monitors', 'reachable_from', 'reaches'])

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

function classifyRelation(relationType: string): Pick<TopologyLink, 'kind' | 'layer'> {
  const normalized = relationType.trim().toLowerCase().replace(/[ -]+/g, '_')
  if (physicalRelationTypes.has(normalized)) {
    return { kind: 'physical', layer: 'physical' }
  }
  if (membershipRelationTypes.has(normalized)) {
    return { kind: 'membership', layer: 'logical' }
  }
  if (gatewayRelationTypes.has(normalized)) {
    return { kind: 'gateway', layer: 'logical' }
  }
  if (logicalRelationTypes.has(normalized)) {
    return { kind: 'logical', layer: 'logical' }
  }
  if (reachabilityRelationTypes.has(normalized)) {
    return { kind: 'reachability', layer: 'reachability' }
  }
  return { kind: 'unknown', layer: 'unknown' }
}

function parseIPv4(value: string): number | null {
  const parts = value.trim().split('.')
  if (parts.length !== 4) {
    return null
  }
  let result = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return null
    }
    const octet = Number(part)
    if (octet < 0 || octet > 255) {
      return null
    }
    result = result * 256 + octet
  }
  return result >>> 0
}

function matchingIPv4Prefix(ipAddress: string, cidr: string): number | null {
  const [networkAddress, prefixText, ...rest] = cidr.trim().split('/')
  if (rest.length > 0 || prefixText === undefined || !/^\d{1,2}$/.test(prefixText)) {
    return null
  }
  const ip = parseIPv4(ipAddress)
  const network = parseIPv4(networkAddress)
  const prefix = Number(prefixText)
  if (ip === null || network === null || prefix < 0 || prefix > 32) {
    return null
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  return (ip & mask) === (network & mask) ? prefix : null
}

function mostSpecificSegment(ipAddress: string, segments: NetworkSegment[]): NetworkSegment | null {
  const matches = segments.flatMap((segment) => {
    const prefix = matchingIPv4Prefix(ipAddress, segment.cidr)
    return prefix === null ? [] : [{ segment, prefix }]
  })
  if (matches.length === 0) {
    return null
  }
  const bestPrefix = Math.max(...matches.map((match) => match.prefix))
  const best = matches.filter((match) => match.prefix === bestPrefix)
  return best.length === 1 ? best[0].segment : null
}

function endpointPair(source: string, target: string) {
  return source < target ? `${source}\u0000${target}` : `${target}\u0000${source}`
}

function automaticLinkID(kind: TopologyLinkKind, source: string, target: string) {
  return `auto:${kind}:${encodeURIComponent(source)}:${encodeURIComponent(target)}`
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
  const occupiedPairs = new Set<string>()
  const appendLink = (link: TopologyLink) => {
    const sourceEntity = entityById.get(link.source)
    const targetEntity = entityById.get(link.target)
    if (!sourceEntity || !targetEntity) {
      return
    }
    sourceEntity.connectionCount += 1
    targetEntity.connectionCount += 1
    links.push(link)
    occupiedPairs.add(endpointPair(link.source, link.target))
  }
  relations.forEach((relation) => {
    const source = topologyEntityKey(relation.sourceKind, relation.sourceId)
    const target = topologyEntityKey(relation.targetKind, relation.targetId)
    if (!entityById.has(source) || !entityById.has(target)) {
      return
    }
    const label = relation.relationType.replace(/[_-]+/g, ' ')
    const confidence = normalizeConfidence(relation.confidence)
    const semantics = classifyRelation(relation.relationType)
    appendLink({
      id: relation.id,
      source,
      target,
      label,
      confidence,
      ...semantics,
      evidence: {
        source: relation.metadata?.evidenceSource?.trim() || (confidence === 'manual' ? 'manual relation' : 'stored relation'),
        detail: relation.metadata?.evidenceDetail?.trim() || label,
        automatic: false,
        ...(relation.observedAt ? { observedAt: relation.observedAt } : {}),
      },
      raw: relation,
    })
  })

  const appendAutomaticLink = (
    source: string,
    target: string,
    kind: TopologyLinkKind,
    label: string,
    confidence: TopologyConfidence,
    evidenceSource: string,
    evidenceDetail: string,
  ) => {
    if (occupiedPairs.has(endpointPair(source, target))) {
      return
    }
    appendLink({
      id: automaticLinkID(kind, source, target),
      source,
      target,
      label,
      confidence,
      layer: 'logical',
      kind,
      evidence: {
        source: evidenceSource,
        detail: evidenceDetail,
        automatic: true,
      },
    })
  }

  const segmentById = new Map(networkSegments.map((segment) => [segment.id, segment]))
  devices.forEach((device) => {
    const configuredSegment = segmentById.get(device.networkSegment)
    const segment = configuredSegment ?? mostSpecificSegment(device.ipAddress, networkSegments)
    if (!segment) {
      return
    }
    const segmentId = topologyEntityKey('networkSegment', segment.id)
    const deviceId = topologyEntityKey('device', device.id)
    const vlanLabel = segment.vlanId ? `VLAN ${segment.vlanId}` : segment.name
    appendAutomaticLink(
      segmentId,
      deviceId,
      'membership',
      `member of ${vlanLabel}`,
      configuredSegment ? 'manual' : 'inferred',
      configuredSegment ? 'inventory.networkSegment' : 'cidr-match',
      configuredSegment
        ? `Configured segment ${segment.name}`
        : `${device.ipAddress} is inside ${segment.cidr}`,
    )
  })

  networkNodes.forEach((node) => {
    const nodeId = topologyEntityKey('networkNode', node.id)
    const gatewaySegments = networkSegments.filter((segment) => (
      segment.gatewayIp !== '' && segment.gatewayIp === node.managementIp
    ))
    if (gatewaySegments.length > 0) {
      gatewaySegments.forEach((segment) => appendAutomaticLink(
        topologyEntityKey('networkSegment', segment.id),
        nodeId,
        'gateway',
        'gateway',
        'inferred',
        'segment.gatewayIp',
        `${node.managementIp} matches the configured gateway for ${segment.name}`,
      ))
      return
    }
    const segment = mostSpecificSegment(node.managementIp, networkSegments)
    if (segment) {
      appendAutomaticLink(
        topologyEntityKey('networkSegment', segment.id),
        nodeId,
        'management',
        'managed on',
        'inferred',
        'cidr-match',
        `${node.managementIp} is inside ${segment.cidr}`,
      )
    }
  })

  return { entities, links }
}

export function entityMatchesFilters(entity: TopologyEntity, filters: TopologyFilters) {
  const query = filters.query.trim().toLocaleLowerCase()
  return filters.kinds.has(entity.kind)
    && filters.statuses.has(entity.status)
    && (!query || entity.searchText.includes(query))
}

export function visibleTopologyIds(model: TopologyModel, filters: TopologyFilters) {
  const candidateEntityIds = new Set(model.entities.filter((entity) => entityMatchesFilters(entity, filters)).map((entity) => entity.id))
  const candidateLinks = model.links.filter((link) => (
    candidateEntityIds.has(link.source)
    && candidateEntityIds.has(link.target)
    && filters.confidences.has(link.confidence)
    && filters.layers.has(link.layer)
  ))
  const linkedEntityIds = new Set(candidateLinks.flatMap((link) => [link.source, link.target]))
  const entityIds = filters.linkState === 'all'
    ? candidateEntityIds
    : new Set([...candidateEntityIds].filter((id) => (
      filters.linkState === 'linked' ? linkedEntityIds.has(id) : !linkedEntityIds.has(id)
    )))
  const linkIds = new Set(candidateLinks.filter((link) => (
    entityIds.has(link.source) && entityIds.has(link.target)
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
