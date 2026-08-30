import { describe, expect, it } from 'vitest'
import { topologyEntityKey } from '../src/frontend-utils'
import type { Device, NetworkNode, NetworkSegment, Relation } from '../src/models'
import {
  allTopologyConfidences,
  allTopologyKinds,
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
    const unlinked = { ...device, id: 'unlinked', name: 'Unlinked endpoint' }
    const model = buildTopologyModel([device, unlinked], [node], [segment], relations)
    const visible = visibleTopologyIds(model, {
      query: '',
      kinds: new Set(allTopologyKinds),
      statuses: new Set(allTopologyStatuses),
      confidences: new Set(allTopologyConfidences),
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
})
