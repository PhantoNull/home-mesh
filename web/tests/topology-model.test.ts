import { describe, expect, it } from 'vitest'
import { topologyEntityKey } from '../src/frontend-utils'
import type { Device, NetworkNode, NetworkSegment, Relation } from '../src/models'
import {
  allTopologyConfidences,
  allTopologyKinds,
  allTopologyLayers,
  allTopologyStatuses,
  buildTopologyModel,
  connectedTopologyIds,
  fallbackTopologyPositions,
  scalableTopologyPositions,
  visibleTopologyIds,
} from '../src/topology-model'

const device: Device = {
  id: 'shared',
  version: 1,
  name: 'NAS Alpha',
  hostname: 'nas.local',
  role: 'storage',
  deviceType: 'nas',
  ipAddress: '192.168.1.16',
  macAddress: '00:11:22:33:44:55',
  networkSegment: 'lan',
  status: 'online',
  tags: ['nas'],
}

const node: NetworkNode = {
  id: 'shared',
  version: 1,
  name: 'Core router',
  nodeType: 'router',
  managementIp: '192.168.1.1',
  macAddress: '',
  vendor: 'Example',
  model: 'R1',
  status: 'degraded',
  tags: [],
}

const segment: NetworkSegment = {
  id: 'lan',
  version: 1,
  name: 'Main LAN',
  segmentType: 'lan',
  cidr: '192.168.1.0/24',
  vlanId: 0,
  gatewayIp: '192.168.1.1',
  dnsDomain: 'local',
}

const relations: Relation[] = [
  {
    id: 'router-segment',
    version: 1,
    sourceKind: 'networkNode',
    sourceId: node.id,
    targetKind: 'networkSegment',
    targetId: segment.id,
    relationType: 'routes_for',
    confidence: 'observed',
  },
  {
    id: 'device-segment',
    version: 1,
    sourceKind: 'device',
    sourceId: device.id,
    targetKind: 'networkSegment',
    targetId: segment.id,
    relationType: 'member_of_segment',
    confidence: 'manual',
  },
  {
    id: 'orphan',
    version: 1,
    sourceKind: 'device',
    sourceId: 'missing',
    targetKind: 'networkSegment',
    targetId: segment.id,
    relationType: 'member_of_segment',
    confidence: 'manual',
  },
]

describe('topology model', () => {
  it('keeps equal IDs in different entity kinds distinct and excludes orphan relations', () => {
    const model = buildTopologyModel([device], [node], [segment], relations)
    expect(model.entities.map((entity) => entity.id)).toEqual([
      topologyEntityKey('networkSegment', 'lan'),
      topologyEntityKey('networkNode', 'shared'),
      topologyEntityKey('device', 'shared'),
    ])
    expect(model.links).toHaveLength(2)
    expect(model.entities.map((entity) => entity.connectionCount)).toEqual([2, 1, 1])
  })

  it('indexes operational identifiers for case-insensitive search', () => {
    const model = buildTopologyModel([device], [node], [segment], relations)
    const visible = visibleTopologyIds(model, {
      query: 'NAS.LOCAL',
      kinds: new Set(allTopologyKinds),
      statuses: new Set(allTopologyStatuses),
      confidences: new Set(allTopologyConfidences),
      layers: new Set(allTopologyLayers),
      linkState: 'all',
    })
    expect([...visible.entityIds]).toEqual([topologyEntityKey('device', 'shared')])
    expect(visible.linkIds.size).toBe(0)
  })

  it('filters edges by confidence without inventing membership links', () => {
    const model = buildTopologyModel([device], [node], [segment], relations)
    const visible = visibleTopologyIds(model, {
      query: '',
      kinds: new Set(allTopologyKinds),
      statuses: new Set(allTopologyStatuses),
      confidences: new Set(['observed']),
      layers: new Set(allTopologyLayers),
      linkState: 'all',
    })
    expect([...visible.linkIds]).toEqual(['router-segment'])
    expect(model.links.some((link) => link.id === 'device-segment')).toBe(true)
  })

  it('returns exactly the selected one-hop neighborhood', () => {
    const model = buildTopologyModel([device], [node], [segment], relations)
    const connected = connectedTopologyIds(model, topologyEntityKey('networkSegment', 'lan'))
    expect(connected.entityIds).toEqual(new Set([
      topologyEntityKey('networkSegment', 'lan'),
      topologyEntityKey('networkNode', 'shared'),
      topologyEntityKey('device', 'shared'),
    ]))
    expect(connected.linkIds).toEqual(new Set(['router-segment', 'device-segment']))
  })

  it('isolates unlinked entities without changing relation truth', () => {
    const unlinked = { ...device, id: 'unlinked', name: 'Unlinked endpoint', ipAddress: '203.0.113.20', networkSegment: '' }
    const model = buildTopologyModel([device, unlinked], [node], [segment], relations)
    const visible = visibleTopologyIds(model, {
      query: '',
      kinds: new Set(allTopologyKinds),
      statuses: new Set(allTopologyStatuses),
      confidences: new Set(allTopologyConfidences),
      layers: new Set(allTopologyLayers),
      linkState: 'unlinked',
    })
    expect([...visible.entityIds]).toEqual([topologyEntityKey('device', 'unlinked')])
    expect(visible.linkIds.size).toBe(0)
  })

  it('produces deterministic non-overlapping fallback positions in both directions', () => {
    const ids = ['a', 'b', 'c', 'd']
    const horizontal = fallbackTopologyPositions(ids, 'RIGHT')
    const vertical = fallbackTopologyPositions(ids, 'DOWN')
    expect(new Set([...horizontal.values()].map(({ x, y }) => `${x}:${y}`)).size).toBe(ids.length)
    expect(new Set([...vertical.values()].map(({ x, y }) => `${x}:${y}`)).size).toBe(ids.length)
    expect(horizontal.get('b')).not.toEqual(vertical.get('b'))
  })

  it('groups large topology positions into ordered kind bands', () => {
    const entities = [
      { id: 'segment', kind: 'segment' as const },
      { id: 'node-a', kind: 'node' as const },
      { id: 'node-b', kind: 'node' as const },
      { id: 'device', kind: 'device' as const },
    ]
    const horizontal = scalableTopologyPositions(entities, 'RIGHT')
    const vertical = scalableTopologyPositions(entities, 'DOWN')
    expect(horizontal.get('segment')!.x).toBeLessThan(horizontal.get('node-a')!.x)
    expect(horizontal.get('node-b')!.x).toBeLessThan(horizontal.get('device')!.x)
    expect(vertical.get('segment')!.y).toBeLessThan(vertical.get('node-a')!.y)
    expect(vertical.get('node-b')!.y).toBeLessThan(vertical.get('device')!.y)
  })

  it('projects configured segment membership and gateway evidence automatically', () => {
    const model = buildTopologyModel([device], [node], [segment], [])

    expect(model.links).toEqual(expect.arrayContaining([
      expect.objectContaining({
        source: topologyEntityKey('networkSegment', segment.id),
        target: topologyEntityKey('device', device.id),
        kind: 'membership',
        layer: 'logical',
        confidence: 'manual',
        evidence: expect.objectContaining({ source: 'inventory.networkSegment', automatic: true }),
      }),
      expect.objectContaining({
        source: topologyEntityKey('networkSegment', segment.id),
        target: topologyEntityKey('networkNode', node.id),
        kind: 'gateway',
        layer: 'logical',
        confidence: 'inferred',
        evidence: expect.objectContaining({ source: 'segment.gatewayIp', automatic: true }),
      }),
    ]))
    expect(model.entities.map((entity) => entity.connectionCount)).toEqual([2, 1, 1])
  })

  it('uses the most-specific unambiguous CIDR for otherwise unassigned inventory', () => {
    const broad = { ...segment, id: 'broad', name: 'Broad LAN', cidr: '192.168.0.0/16', gatewayIp: '' }
    const specific = { ...segment, id: 'specific', name: 'Storage VLAN', cidr: '192.168.1.0/24', gatewayIp: '' }
    const unassigned = { ...device, id: 'unassigned', networkSegment: '' }
    const managedNode = { ...node, id: 'switch', nodeType: 'switch', managementIp: '192.168.1.2' }
    const model = buildTopologyModel([unassigned], [managedNode], [broad, specific], [])

    expect(model.links).toEqual(expect.arrayContaining([
      expect.objectContaining({
        source: topologyEntityKey('networkSegment', specific.id),
        target: topologyEntityKey('device', unassigned.id),
        kind: 'membership',
        confidence: 'inferred',
        evidence: expect.objectContaining({ source: 'cidr-match' }),
      }),
      expect.objectContaining({
        source: topologyEntityKey('networkSegment', specific.id),
        target: topologyEntityKey('networkNode', managedNode.id),
        kind: 'management',
        confidence: 'inferred',
      }),
    ]))
    expect(model.links.some((link) => link.source === topologyEntityKey('networkSegment', broad.id))).toBe(false)
  })

  it('keeps explicit physical evidence authoritative and does not duplicate its endpoints', () => {
    const physical: Relation = {
      id: 'switch-nas-port',
      version: 1,
      sourceKind: 'networkNode',
      sourceId: node.id,
      targetKind: 'device',
      targetId: device.id,
      relationType: 'connected_to',
      confidence: 'observed',
      metadata: { evidenceSource: 'lldp', localPort: 'Gi0/8' },
      observedAt: '2026-08-30T20:00:00Z',
    }
    const model = buildTopologyModel([device], [node], [segment], [physical])
    const link = model.links.find((candidate) => candidate.id === physical.id)

    expect(link).toMatchObject({
      kind: 'physical',
      layer: 'physical',
      evidence: {
        source: 'lldp',
        detail: 'connected to',
        automatic: false,
        observedAt: physical.observedAt,
      },
    })
    const physicalOnly = visibleTopologyIds(model, {
      query: '',
      kinds: new Set(allTopologyKinds),
      statuses: new Set(allTopologyStatuses),
      confidences: new Set(allTopologyConfidences),
      layers: new Set(['physical']),
      linkState: 'all',
    })
    expect([...physicalOnly.linkIds]).toEqual([physical.id])
    const missingPhysical = visibleTopologyIds(model, {
      query: '',
      kinds: new Set(allTopologyKinds),
      statuses: new Set(allTopologyStatuses),
      confidences: new Set(allTopologyConfidences),
      layers: new Set(['physical']),
      linkState: 'unlinked',
    })
    expect([...missingPhysical.entityIds]).toEqual([topologyEntityKey('networkSegment', segment.id)])
    expect(model.links.filter((candidate) => (
      new Set([candidate.source, candidate.target]).has(topologyEntityKey('networkNode', node.id))
      && new Set([candidate.source, candidate.target]).has(topologyEntityKey('device', device.id))
    ))).toHaveLength(1)
  })
})
