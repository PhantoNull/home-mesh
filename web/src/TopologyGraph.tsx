import { type KeyboardEvent, useState } from 'react'
import {
  Cable,
  Maximize2,
  Router,
  Server,
  Tags,
  ZoomIn,
  ZoomOut,
} from 'lucide-react'
import { topologyEntityKey, truncateTopologyLabel } from './frontend-utils'
import {
  type Device,
  type NetworkNode,
  type NetworkSegment,
  type Relation,
} from './models'

type TopologyNodeKind = 'segment' | 'node' | 'device'
type TopologyNodeStatus = 'online' | 'offline' | 'degraded' | 'unknown' | 'configured'
type TopologyAnchorSide = 'top' | 'right' | 'bottom' | 'left'

type TopologyNode = {
  id: string
  key: string
  kind: TopologyNodeKind
  entityKind: Relation['sourceKind']
  label: string
  subtitle: string
  detail: string
  status: TopologyNodeStatus
  x: number
  y: number
  connectionCount: number
}

type TopologyEdge = {
  id: string
  label: string
  confidence: string
  style: 'manual' | 'observed' | 'inferred'
  sourceKey: string
  targetKey: string
  x1: number
  y1: number
  x2: number
  y2: number
  c1x: number
  c1y: number
  c2x: number
  c2y: number
  labelX: number
  labelY: number
  labelWidth: number
}

type TopologyAnchor = {
  x: number
  y: number
  side: TopologyAnchorSide
}

type TopologyGraphProps = {
  devices: Device[]
  networkNodes: NetworkNode[]
  networkSegments: NetworkSegment[]
  relations: Relation[]
}

const graphWidth = 1040
const nodeWidth = 238
const nodeHeight = 86
const nodeHalfWidth = nodeWidth / 2
const nodeHalfHeight = nodeHeight / 2

const laneX: Record<TopologyNodeKind, number> = {
  segment: 160,
  node: 520,
  device: 880,
}

function normalizeStatus(status: string): TopologyNodeStatus {
  const normalized = status.trim().toLowerCase()
  if (normalized === 'online' || normalized === 'offline' || normalized === 'degraded') {
    return normalized
  }
  return 'unknown'
}

function edgeStyle(confidence: string): TopologyEdge['style'] {
  const normalized = confidence.trim().toLowerCase()
  if (normalized === 'manual') {
    return 'manual'
  }
  if (normalized === 'observed' || normalized === 'confirmed') {
    return 'observed'
  }
  return 'inferred'
}

function displayRelationType(relationType: string) {
  return truncateTopologyLabel(relationType.replace(/_/g, ' '), 24)
}

function anchorForDirection(node: TopologyNode, toward: Pick<TopologyNode, 'x' | 'y'>): TopologyAnchor {
  const dx = toward.x - node.x
  const dy = toward.y - node.y

  if (Math.abs(dx) >= Math.abs(dy)) {
    return dx >= 0
      ? { x: node.x + nodeHalfWidth, y: node.y, side: 'right' }
      : { x: node.x - nodeHalfWidth, y: node.y, side: 'left' }
  }

  return dy >= 0
    ? { x: node.x, y: node.y + nodeHalfHeight, side: 'bottom' }
    : { x: node.x, y: node.y - nodeHalfHeight, side: 'top' }
}

function controlPoint(anchor: TopologyAnchor) {
  const offset = 88
  switch (anchor.side) {
    case 'right':
      return { x: anchor.x + offset, y: anchor.y }
    case 'left':
      return { x: anchor.x - offset, y: anchor.y }
    case 'bottom':
      return { x: anchor.x, y: anchor.y + offset }
    case 'top':
      return { x: anchor.x, y: anchor.y - offset }
  }
}

function nodeKindLabel(kind: TopologyNodeKind) {
  switch (kind) {
    case 'segment':
      return 'Segment'
    case 'node':
      return 'Network node'
    case 'device':
      return 'Device'
  }
}

export default function TopologyGraph({
  devices,
  networkNodes,
  networkSegments,
  relations,
}: TopologyGraphProps) {
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [showLabels, setShowLabels] = useState(true)
  const [zoom, setZoom] = useState(1)

  if (
    devices.length === 0
    && networkNodes.length === 0
    && networkSegments.length === 0
    && relations.length === 0
  ) {
    return <div className="empty-state">Empty</div>
  }

  const laneCounts = [networkSegments.length, networkNodes.length, devices.length]
  const maxLaneItems = Math.max(...laneCounts, 1)
  const graphHeight = Math.max(390, 154 + maxLaneItems * 116)
  const firstNodeY = maxLaneItems === 1 ? Math.round(graphHeight / 2) + 18 : 132

  const buildLaneNodes = <T extends { id: string; name: string }>(
    items: T[],
    kind: TopologyNodeKind,
    entityKind: Relation['sourceKind'],
    subtitle: (item: T) => string,
    detail: (item: T) => string,
    status: (item: T) => TopologyNodeStatus,
  ): TopologyNode[] => items.map((item, index) => ({
    id: item.id,
    key: topologyEntityKey(entityKind, item.id),
    kind,
    entityKind,
    label: item.name,
    subtitle: subtitle(item),
    detail: detail(item),
    status: status(item),
    x: laneX[kind],
    y: firstNodeY + index * 116,
    connectionCount: 0,
  }))

  const nodesWithoutCounts = [
    ...buildLaneNodes(
      networkSegments,
      'segment',
      'networkSegment',
      (segment) => segment.cidr || segment.segmentType || 'Network segment',
      (segment) => segment.gatewayIp || segment.dnsDomain || 'Configured segment',
      () => 'configured',
    ),
    ...buildLaneNodes(
      networkNodes,
      'node',
      'networkNode',
      (node) => node.managementIp || node.nodeType || 'Network node',
      (node) => [node.vendor, node.model].filter(Boolean).join(' ') || node.nodeType || 'Infrastructure',
      (node) => normalizeStatus(node.status),
    ),
    ...buildLaneNodes(
      devices,
      'device',
      'device',
      (device) => device.ipAddress || device.hostname || 'Managed device',
      (device) => device.role || device.deviceType || 'Endpoint',
      (device) => normalizeStatus(device.status),
    ),
  ]

  const knownKeys = new Set(nodesWithoutCounts.map((node) => node.key))
  const connectionCounts = new Map<string, number>()
  relations.forEach((relation) => {
    const sourceKey = topologyEntityKey(relation.sourceKind, relation.sourceId)
    const targetKey = topologyEntityKey(relation.targetKind, relation.targetId)
    if (!knownKeys.has(sourceKey) || !knownKeys.has(targetKey)) {
      return
    }
    connectionCounts.set(sourceKey, (connectionCounts.get(sourceKey) ?? 0) + 1)
    connectionCounts.set(targetKey, (connectionCounts.get(targetKey) ?? 0) + 1)
  })

  const graphNodes = nodesWithoutCounts.map((node) => ({
    ...node,
    connectionCount: connectionCounts.get(node.key) ?? 0,
  }))
  const nodeLookup = new Map(graphNodes.map((node) => [node.key, node]))

  const graphEdges: TopologyEdge[] = []
  relations.forEach((relation, relationIndex) => {
    const sourceKey = topologyEntityKey(relation.sourceKind, relation.sourceId)
    const targetKey = topologyEntityKey(relation.targetKind, relation.targetId)
    const source = nodeLookup.get(sourceKey)
    const target = nodeLookup.get(targetKey)
    if (!source || !target) {
      return
    }

    const start = anchorForDirection(source, target)
    const end = anchorForDirection(target, source)
    const c1 = controlPoint(start)
    const c2 = controlPoint(end)
    const crossesLanes = Math.abs(target.x - source.x) > nodeWidth
    const label = displayRelationType(relation.relationType)

    graphEdges.push({
      id: relation.id,
      label,
      confidence: relation.confidence,
      style: edgeStyle(relation.confidence),
      sourceKey,
      targetKey,
      x1: start.x,
      y1: start.y,
      x2: end.x,
      y2: end.y,
      c1x: c1.x,
      c1y: c1.y,
      c2x: c2.x,
      c2y: c2.y,
      labelX: crossesLanes ? (start.x + end.x) / 2 : start.x + nodeHalfWidth + 54,
      labelY: (start.y + end.y) / 2 - 10 + (relationIndex % 2) * 18,
      labelWidth: Math.max(54, label.length * 6.4 + 18),
    })
  })

  const selectedNode = selectedKey ? nodeLookup.get(selectedKey) : undefined
  const connectedKeys = new Set<string>()
  if (selectedKey) {
    connectedKeys.add(selectedKey)
    graphEdges.forEach((edge) => {
      if (edge.sourceKey === selectedKey) {
        connectedKeys.add(edge.targetKey)
      }
      if (edge.targetKey === selectedKey) {
        connectedKeys.add(edge.sourceKey)
      }
    })
  }

  const onlineCount = graphNodes.filter((node) => node.status === 'online').length
  const unlinkedCount = graphNodes.filter((node) => node.connectionCount === 0).length
  const zoomPercentage = Math.round(zoom * 100)

  const toggleNode = (key: string) => {
    setSelectedKey((current) => current === key ? null : key)
  }

  const handleNodeKeyDown = (event: KeyboardEvent<SVGGElement>, key: string) => {
    if (event.key !== 'Enter' && event.key !== ' ') {
      return
    }
    event.preventDefault()
    toggleNode(key)
  }

  return (
    <div className="topology-graph">
      <div className="topology-graph__toolbar">
        <div className="topology-graph__stats" aria-label="Topology summary">
          <span className="topology-stat"><strong>{graphNodes.length}</strong> entities</span>
          <span className="topology-stat"><strong>{graphEdges.length}</strong> links</span>
          <span className="topology-stat topology-stat--online"><strong>{onlineCount}</strong> online</span>
          {unlinkedCount > 0 ? <span className="topology-stat topology-stat--warning"><strong>{unlinkedCount}</strong> unlinked</span> : null}
        </div>

        <div className="topology-graph__controls" aria-label="Topology view controls">
          <button
            type="button"
            className="topology-control-button"
            onClick={() => setZoom((current) => Math.max(0.75, current - 0.25))}
            disabled={zoom <= 0.75}
            aria-label="Zoom out topology"
            title="Zoom out"
          >
            <ZoomOut aria-hidden="true" />
          </button>
          <span className="topology-graph__zoom" aria-live="polite">{zoomPercentage}%</span>
          <button
            type="button"
            className="topology-control-button"
            onClick={() => setZoom((current) => Math.min(1.5, current + 0.25))}
            disabled={zoom >= 1.5}
            aria-label="Zoom in topology"
            title="Zoom in"
          >
            <ZoomIn aria-hidden="true" />
          </button>
          <button
            type="button"
            className="topology-control-button"
            onClick={() => setZoom(1)}
            disabled={zoom === 1}
            aria-label="Reset topology zoom"
            title="Reset zoom"
          >
            <Maximize2 aria-hidden="true" />
          </button>
          <button
            type="button"
            className={`topology-control-button${showLabels ? ' topology-control-button--active' : ''}`}
            onClick={() => setShowLabels((current) => !current)}
            aria-label="Toggle relation labels"
            aria-pressed={showLabels}
            title="Relation labels"
          >
            <Tags aria-hidden="true" />
          </button>
        </div>
      </div>

      <div className="topology-graph__context-row">
        <div className="topology-graph__legend" aria-label="Topology legend">
          <span className="topology-legend-item"><span className="topology-legend-swatch topology-legend-swatch--segment" />Segments</span>
          <span className="topology-legend-item"><span className="topology-legend-swatch topology-legend-swatch--node" />Network nodes</span>
          <span className="topology-legend-item"><span className="topology-legend-swatch topology-legend-swatch--device" />Devices</span>
        </div>
        {selectedNode ? (
          <div className="topology-graph__selection" aria-live="polite">
            <span>{nodeKindLabel(selectedNode.kind)}</span>
            <strong>{selectedNode.label}</strong>
            <span>{selectedNode.connectionCount} {selectedNode.connectionCount === 1 ? 'link' : 'links'}</span>
          </div>
        ) : null}
      </div>

      <div className="topology-graph__canvas" role="region" aria-label="Scrollable network topology" tabIndex={0}>
        <svg
          viewBox={`0 0 ${graphWidth} ${graphHeight}`}
          className="topology-graph__svg"
          role="group"
          aria-label="Network topology graph"
          style={{ width: `${zoom * 100}%`, minWidth: `${graphWidth * zoom}px` }}
        >
          <desc>Network segments, infrastructure nodes, devices, and the relations between them.</desc>
          <defs>
            <pattern id="topology-grid" width="24" height="24" patternUnits="userSpaceOnUse">
              <path d="M 24 0 L 0 0 0 24" className="topology-graph__grid-line" />
            </pattern>
            <marker id="topology-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
              <path d="M 0 0 L 8 4 L 0 8 z" className="topology-graph__arrow" />
            </marker>
          </defs>

          <rect width={graphWidth} height={graphHeight} className="topology-graph__background" />
          <rect width={graphWidth} height={graphHeight} fill="url(#topology-grid)" />

          {(['segment', 'node', 'device'] as const).map((kind) => (
            <g key={kind}>
              <rect
                x={laneX[kind] - 145}
                y="58"
                width="290"
                height={graphHeight - 76}
                rx="8"
                className={`topology-graph__lane topology-graph__lane--${kind}`}
              />
              <text x={laneX[kind]} y="35" textAnchor="middle" className="topology-graph__lane-label">
                {kind === 'segment' ? 'Segments' : kind === 'node' ? 'Network nodes' : 'Devices'}
              </text>
              <text x={laneX[kind]} y="51" textAnchor="middle" className="topology-graph__lane-count">
                {kind === 'segment' ? networkSegments.length : kind === 'node' ? networkNodes.length : devices.length}
              </text>
            </g>
          ))}

          <g className="topology-graph__edges">
            {graphEdges.map((edge) => {
              const active = selectedKey === null || edge.sourceKey === selectedKey || edge.targetKey === selectedKey
              return (
                <g key={edge.id} className={active ? '' : 'topology-graph__edge-group--dimmed'}>
                  <title>{`${edge.label}${edge.confidence ? ` (${edge.confidence})` : ''}`}</title>
                  <path
                    d={`M ${edge.x1} ${edge.y1} C ${edge.c1x} ${edge.c1y}, ${edge.c2x} ${edge.c2y}, ${edge.x2} ${edge.y2}`}
                    className={`topology-graph__edge topology-graph__edge--${edge.style}${selectedKey && active ? ' topology-graph__edge--active' : ''}`}
                    markerEnd="url(#topology-arrow)"
                  />
                  {showLabels || (selectedKey !== null && active) ? (
                    <g transform={`translate(${edge.labelX}, ${edge.labelY})`} className="topology-graph__edge-label-group">
                      <rect
                        x={-edge.labelWidth / 2}
                        y="-11"
                        width={edge.labelWidth}
                        height="18"
                        rx="4"
                        className="topology-graph__edge-label-background"
                      />
                      <text x="0" y="2" textAnchor="middle" className="topology-graph__edge-label">
                        {edge.label}
                      </text>
                    </g>
                  ) : null}
                </g>
              )
            })}
          </g>

          <g className="topology-graph__nodes">
            {graphNodes.map((node) => {
              const selected = selectedKey === node.key
              const dimmed = selectedKey !== null && !connectedKeys.has(node.key)
              const NodeIcon = node.kind === 'segment' ? Cable : node.kind === 'node' ? Router : Server
              return (
                <g
                  key={node.key}
                  transform={`translate(${node.x - nodeHalfWidth}, ${node.y - nodeHalfHeight})`}
                  className={`topology-graph__node-group${selected ? ' topology-graph__node-group--selected' : ''}${dimmed ? ' topology-graph__node-group--dimmed' : ''}`}
                  role="button"
                  tabIndex={0}
                  aria-pressed={selected}
                  aria-label={`${nodeKindLabel(node.kind)} ${node.label}, ${node.status}, ${node.connectionCount} ${node.connectionCount === 1 ? 'link' : 'links'}`}
                  onClick={() => toggleNode(node.key)}
                  onKeyDown={(event) => handleNodeKeyDown(event, node.key)}
                >
                  <title>{`${node.label}: ${node.subtitle} - ${node.detail}`}</title>
                  <rect
                    width={nodeWidth}
                    height={nodeHeight}
                    rx="7"
                    className={`topology-graph__node topology-graph__node--${node.kind}`}
                  />
                  <rect
                    width="4"
                    height={nodeHeight - 18}
                    x="0"
                    y="9"
                    rx="2"
                    className={`topology-graph__status-rail topology-graph__status-rail--${node.status}`}
                  />
                  <NodeIcon x="16" y="19" width="21" height="21" className="topology-graph__node-icon" aria-hidden="true" />
                  <text x="49" y="27" className="topology-graph__node-title">
                    {truncateTopologyLabel(node.label, 24)}
                  </text>
                  <text x="49" y="47" className="topology-graph__node-subtitle">
                    {truncateTopologyLabel(node.subtitle, 28)}
                  </text>
                  <circle cx="22" cy="65" r="4" className={`topology-graph__status-dot topology-graph__status-dot--${node.status}`} />
                  <text x="34" y="69" className="topology-graph__node-meta">
                    {node.status}
                  </text>
                  <text x={nodeWidth - 14} y="69" textAnchor="end" className="topology-graph__node-meta">
                    {node.connectionCount} {node.connectionCount === 1 ? 'link' : 'links'}
                  </text>
                </g>
              )
            })}
          </g>
        </svg>
      </div>
    </div>
  )
}
