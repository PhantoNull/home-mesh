import type { TopologyDirection, TopologyKind } from './topology-model'

export type TopologyLayoutRequest = {
  requestId: number
  revision: number
  direction: TopologyDirection
  nodes: Array<{ id: string; kind: TopologyKind; width: number; height: number }>
  edges: Array<{ id: string; source: string; target: string }>
}

export type TopologyLayoutSuccess = {
  requestId: number
  ok: true
  positions: Array<{ id: string; x: number; y: number }>
}

export type TopologyLayoutFailure = {
  requestId: number
  ok: false
  error: string
}

export type TopologyLayoutResponse = TopologyLayoutSuccess | TopologyLayoutFailure
