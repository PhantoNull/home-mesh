import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useNodesState,
  useReactFlow,
  type Edge,
} from '@xyflow/react'
import {
  Cable,
  Columns3,
  ExternalLink,
  LocateFixed,
  Network,
  Pencil,
  Power,
  RotateCcw,
  Rows3,
  Search,
  SlidersHorizontal,
  Tags,
  TerminalSquare,
  X,
} from 'lucide-react'
import { getSafePanelLink } from './frontend-utils'
import type { Device, NetworkNode, NetworkSegment, Relation } from './models'
import TopologyEntityNode, { type TopologyFlowNode } from './TopologyEntityNode'
import { layoutTopology } from './topology-layout'
import type { TopologyLayoutRequest, TopologyLayoutResponse } from './topology-layout-protocol'
import {
  allTopologyConfidences,
  allTopologyKinds,
  allTopologyStatuses,
  buildTopologyModel,
  connectedTopologyIds,
  fallbackTopologyPositions,
  scalableTopologyPositions,
  visibleTopologyIds,
  type TopologyConfidence,
  type TopologyDirection,
  type TopologyEntity,
  type TopologyFilters,
  type TopologyKind,
  type TopologyLinkState,
  type TopologyStatus,
} from './topology-model'

type TopologyEdgeData = {
  confidence: TopologyConfidence
  [key: string]: unknown
}

type TopologyFlowEdge = Edge<TopologyEdgeData>

type TopologyGraphProps = {
  devices: Device[]
  networkNodes: NetworkNode[]
  networkSegments: NetworkSegment[]
  relations: Relation[]
  onEditDevice?: (device: Device) => void
  onEditNetworkNode?: (node: NetworkNode) => void
  onEditNetworkSegment?: (segment: NetworkSegment) => void
  onOpenSSH?: (device: Device) => void
  onWake?: (device: Device) => void
}

const topologyNodeWidth = 260
const topologyNodeHeight = 112
const topologyOutlineLimit = 200
const topologyAutomaticLayoutLimit = 500
const topologyCanvasEntityLimit = 300
const nodeTypes = { topologyEntity: TopologyEntityNode }

function kindLabel(kind: TopologyKind) {
  if (kind === 'segment') {
    return 'Segments'
  }
  if (kind === 'node') {
    return 'Network nodes'
  }
  return 'Devices'
}

function statusLabel(status: TopologyStatus) {
  return status.charAt(0).toUpperCase() + status.slice(1)
}

function confidenceLabel(confidence: TopologyConfidence) {
  return confidence.charAt(0).toUpperCase() + confidence.slice(1)
}

function edgeColor(confidence: TopologyConfidence) {
  if (confidence === 'observed') {
    return '#5fc394'
  }
  if (confidence === 'manual') {
    return '#70a9c4'
  }
  return '#d7b45b'
}

function miniMapColor(node: TopologyFlowNode) {
  if (node.data.entity.kind === 'segment') {
    return '#b89843'
  }
  if (node.data.entity.kind === 'node') {
    return '#5592ae'
  }
  return '#4c9c73'
}

function createFlowNodes(entities: TopologyEntity[], direction: TopologyDirection): TopologyFlowNode[] {
  const fallback = entities.length > topologyAutomaticLayoutLimit
    ? scalableTopologyPositions(entities, direction)
    : fallbackTopologyPositions(entities.map((entity) => entity.id), direction)
  return entities.map((entity) => ({
    id: entity.id,
    type: 'topologyEntity',
    position: fallback.get(entity.id) ?? { x: 0, y: 0 },
    data: { entity, direction },
    style: { width: topologyNodeWidth },
    ariaRole: 'button',
    ariaLabel: `${kindLabel(entity.kind).slice(0, -1)} ${entity.label}, ${entity.status}, ${entity.connectionCount} links`,
  }))
}

function createFlowEdges(model: ReturnType<typeof buildTopologyModel>): TopologyFlowEdge[] {
  return model.links.map((link) => ({
    id: link.id,
    source: link.source,
    target: link.target,
    type: 'smoothstep',
    data: { confidence: link.confidence },
    label: link.label,
    markerEnd: { type: MarkerType.ArrowClosed, width: 17, height: 17, color: edgeColor(link.confidence) },
    style: { stroke: edgeColor(link.confidence), strokeWidth: 2 },
    labelStyle: { fill: '#d9dfda', fontSize: 11, fontWeight: 600 },
    labelBgStyle: { fill: '#151a17', fillOpacity: 0.94, stroke: '#39423d', strokeWidth: 1 },
    labelBgPadding: [7, 4],
    labelBgBorderRadius: 4,
    ariaLabel: `${link.label} relation, ${link.confidence}`,
  }))
}

function toggleSetValue<T>(current: ReadonlySet<T>, value: T) {
  const next = new Set(current)
  if (next.has(value)) {
    next.delete(value)
  } else {
    next.add(value)
  }
  return next
}

function entityDetails(entity: TopologyEntity): Array<[string, string]> {
  if (entity.kind === 'device') {
    const device = entity.raw as Device
    return [
      ['IP address', device.ipAddress || 'Not configured'],
      ['Hostname', device.hostname || 'Not configured'],
      ['MAC address', device.macAddress || 'Not configured'],
      ['Role', device.role || device.deviceType || 'Not configured'],
    ]
  }
  if (entity.kind === 'node') {
    const node = entity.raw as NetworkNode
    return [
      ['Management IP', node.managementIp || 'Not configured'],
      ['Type', node.nodeType || 'Not configured'],
      ['MAC address', node.macAddress || 'Not configured'],
      ['Hardware', [node.vendor, node.model].filter(Boolean).join(' ') || 'Not configured'],
    ]
  }
  const segment = entity.raw as NetworkSegment
  return [
    ['CIDR', segment.cidr || 'Not configured'],
    ['Gateway', segment.gatewayIp || 'Not configured'],
    ['VLAN', segment.vlanId ? String(segment.vlanId) : 'Untagged'],
    ['DNS domain', segment.dnsDomain || 'Not configured'],
  ]
}

function TopologyWorkspace({
  devices,
  networkNodes,
  networkSegments,
  relations,
  onEditDevice,
  onEditNetworkNode,
  onEditNetworkSegment,
  onOpenSSH,
  onWake,
}: TopologyGraphProps) {
  const model = useMemo(
    () => buildTopologyModel(devices, networkNodes, networkSegments, relations),
    [devices, networkNodes, networkSegments, relations],
  )
  const [nodes, setNodes, onNodesChange] = useNodesState<TopologyFlowNode>([])
  const [edges, setEdges] = useState<TopologyFlowEdge[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [direction, setDirection] = useState<TopologyDirection>('RIGHT')
  const [showLabels, setShowLabels] = useState(true)
  const [linkState, setLinkState] = useState<TopologyLinkState>('all')
  const [query, setQuery] = useState('')
  const [kinds, setKinds] = useState<ReadonlySet<TopologyKind>>(() => new Set(allTopologyKinds))
  const [statuses, setStatuses] = useState<ReadonlySet<TopologyStatus>>(() => new Set(allTopologyStatuses))
  const [confidences, setConfidences] = useState<ReadonlySet<TopologyConfidence>>(() => new Set(allTopologyConfidences))
  const [layoutRevision, setLayoutRevision] = useState(0)
  const [layoutState, setLayoutState] = useState<'idle' | 'running' | 'ready' | 'fallback' | 'scaled'>('idle')
  const layoutRequestId = useRef(0)
  const { fitView } = useReactFlow<TopologyFlowNode, TopologyFlowEdge>()

  const structureKey = useMemo(() => JSON.stringify({
    nodes: model.entities.map((entity) => [entity.id, entity.kind]),
    edges: model.links.map((link) => [link.id, link.source, link.target]),
  }), [model.entities, model.links])

  useEffect(() => {
    const entityById = new Map(model.entities.map((entity) => [entity.id, entity]))
    setNodes((current) => current.map((node) => {
      const entity = entityById.get(node.id)
      return entity ? { ...node, data: { entity, direction } } : node
    }))
    setEdges(createFlowEdges(model))
  }, [direction, model, setNodes])

  useEffect(() => {
    const initialNodes = createFlowNodes(model.entities, direction)
    const initialEdges = createFlowEdges(model)
    setNodes(initialNodes)
    setEdges(initialEdges)
    if (initialNodes.length === 0) {
      setLayoutState('idle')
      return
    }
    if (initialNodes.length > topologyAutomaticLayoutLimit) {
      setLayoutState('scaled')
      window.requestAnimationFrame(() => void fitView({ padding: 0.12, duration: 220 }))
      return
    }

    const requestId = ++layoutRequestId.current
    let cancelled = false
    const request: TopologyLayoutRequest = {
      requestId,
      revision: layoutRevision,
      direction,
      nodes: model.entities.map((entity) => ({
        id: entity.id,
        kind: entity.kind,
        width: topologyNodeWidth,
        height: topologyNodeHeight,
      })),
      edges: model.links.map((link) => ({ id: link.id, source: link.source, target: link.target })),
    }
    setLayoutState('running')

    const settle = (response: TopologyLayoutResponse) => {
      if (response.requestId !== layoutRequestId.current) {
        return
      }
      if (!response.ok) {
        setLayoutState('fallback')
        window.requestAnimationFrame(() => void fitView({ padding: 0.18, duration: 220 }))
        return
      }
      const positions = new Map(response.positions.map((position) => [position.id, position]))
      setNodes((current) => current.map((node) => ({
        ...node,
        position: positions.get(node.id) ?? node.position,
      })))
      setLayoutState('ready')
      window.requestAnimationFrame(() => void fitView({ padding: 0.18, duration: 320 }))
    }

    const timeout = window.setTimeout(() => {
      if (requestId === layoutRequestId.current) {
        cancelled = true
        setLayoutState('fallback')
        window.requestAnimationFrame(() => void fitView({ padding: 0.18, duration: 220 }))
      }
    }, 8_000)
    void layoutTopology(request).then((response) => {
      if (cancelled) {
        return
      }
      window.clearTimeout(timeout)
      settle(response)
    })

    return () => {
      cancelled = true
      window.clearTimeout(timeout)
    }
  }, [direction, fitView, layoutRevision, setNodes, structureKey])

  const filters: TopologyFilters = useMemo(() => ({
    query,
    kinds,
    statuses,
    confidences,
    linkState,
  }), [confidences, kinds, linkState, query, statuses])
  const visible = useMemo(() => visibleTopologyIds(model, filters), [filters, model])
  const canvasEntityIds = useMemo(() => {
    if (visible.entityIds.size <= topologyCanvasEntityLimit) {
      return visible.entityIds
    }
    return new Set(model.entities
      .filter((entity) => visible.entityIds.has(entity.id))
      .slice(0, topologyCanvasEntityLimit)
      .map((entity) => entity.id))
  }, [model.entities, visible.entityIds])
  const connected = useMemo(() => connectedTopologyIds(model, selectedId), [model, selectedId])
  const selectedEntity = selectedId ? model.entities.find((entity) => entity.id === selectedId) ?? null : null
  const selectedLinks = selectedId ? model.links.filter((link) => link.source === selectedId || link.target === selectedId) : []
  const labelsSuppressedForScale = model.links.length > 300

  useEffect(() => {
    if (selectedId && !visible.entityIds.has(selectedId)) {
      setSelectedId(null)
    }
  }, [selectedId, visible.entityIds])

  const displayNodes = useMemo(() => nodes.filter((node) => canvasEntityIds.has(node.id)).map((node) => ({
    ...node,
    selected: node.id === selectedId,
    className: selectedId && !connected.entityIds.has(node.id) ? 'topology-flow-node--dimmed' : '',
  })), [canvasEntityIds, connected.entityIds, nodes, selectedId])

  const displayEdges = useMemo(() => edges.filter((edge) => (
    visible.linkIds.has(edge.id)
    && canvasEntityIds.has(edge.source)
    && canvasEntityIds.has(edge.target)
  )).map((edge) => {
    const active = !selectedId || connected.linkIds.has(edge.id)
    const confidence = edge.data?.confidence ?? 'inferred'
    return {
      ...edge,
      label: (showLabels && !labelsSuppressedForScale) || (selectedId && active)
        ? model.links.find((link) => link.id === edge.id)?.label
        : undefined,
      className: active ? `topology-flow-edge topology-flow-edge--${confidence}${selectedId ? ' topology-flow-edge--active' : ''}` : 'topology-flow-edge topology-flow-edge--dimmed',
      zIndex: selectedId && active ? 4 : 0,
    }
  }), [canvasEntityIds, connected.linkIds, edges, labelsSuppressedForScale, model.links, selectedId, showLabels, visible.linkIds])

  const resetFilters = useCallback(() => {
    setQuery('')
    setKinds(new Set(allTopologyKinds))
    setStatuses(new Set(allTopologyStatuses))
    setConfidences(new Set(allTopologyConfidences))
    setLinkState('all')
  }, [])

  const filteredEntities = model.entities.filter((entity) => visible.entityIds.has(entity.id))
  const outlineEntities = filteredEntities.slice(0, topologyOutlineLimit)
  const onlineCount = model.entities.filter((entity) => entity.status === 'online').length
  const unlinkedCount = model.entities.filter((entity) => entity.connectionCount === 0).length
  const hasFilters = query.trim() !== ''
    || linkState !== 'all'
    || kinds.size !== allTopologyKinds.length
    || statuses.size !== allTopologyStatuses.length
    || confidences.size !== allTopologyConfidences.length
  const panelLink = selectedEntity ? getSafePanelLink(selectedEntity.raw.metadata) : ''

  const editSelected = () => {
    if (!selectedEntity) {
      return
    }
    if (selectedEntity.kind === 'device') {
      onEditDevice?.(selectedEntity.raw as Device)
    } else if (selectedEntity.kind === 'node') {
      onEditNetworkNode?.(selectedEntity.raw as NetworkNode)
    } else {
      onEditNetworkSegment?.(selectedEntity.raw as NetworkSegment)
    }
  }

  if (model.entities.length === 0) {
    return <div className="topology-empty"><Network aria-hidden="true" /><strong>No topology yet</strong><span>Add inventory entities and relations to build the map.</span></div>
  }

  return (
    <div className="topology-workspace">
      <header className="topology-workspace__toolbar">
        <div className="topology-workspace__stats" aria-label="Topology summary">
          <span><strong>{model.entities.length}</strong> entities</span>
          <span><strong>{model.links.length}</strong> links</span>
          <span className="topology-workspace__online"><strong>{onlineCount}</strong> online</span>
          {unlinkedCount > 0 ? <span className="topology-workspace__warning"><strong>{unlinkedCount}</strong> unlinked</span> : null}
        </div>
        <div className="topology-workspace__view-actions" aria-label="Topology view controls">
          <button type="button" className={direction === 'RIGHT' ? 'icon-button icon-button--active' : 'icon-button'} onClick={() => setDirection('RIGHT')} aria-label="Use horizontal topology layout" aria-pressed={direction === 'RIGHT'} title="Horizontal layout"><Columns3 aria-hidden="true" /></button>
          <button type="button" className={direction === 'DOWN' ? 'icon-button icon-button--active' : 'icon-button'} onClick={() => setDirection('DOWN')} aria-label="Use vertical topology layout" aria-pressed={direction === 'DOWN'} title="Vertical layout"><Rows3 aria-hidden="true" /></button>
          <button type="button" className={showLabels ? 'icon-button icon-button--active' : 'icon-button'} onClick={() => setShowLabels((current) => !current)} aria-label="Toggle relation labels" aria-pressed={showLabels} title="Relation labels"><Tags aria-hidden="true" /></button>
          <button type="button" className="icon-button" onClick={() => setLayoutRevision((current) => current + 1)} aria-label="Recalculate topology layout" title="Recalculate layout"><RotateCcw aria-hidden="true" /></button>
        </div>
      </header>

      {labelsSuppressedForScale && showLabels ? <div className="topology-workspace__notice">Relation labels are shown on selection for this graph size.</div> : null}
      {layoutState === 'scaled' ? <div className="topology-workspace__notice">Fast grouped layout is active for this graph size.</div> : null}
      {visible.entityIds.size > topologyCanvasEntityLimit ? <div className="topology-workspace__notice">The canvas shows the first {topologyCanvasEntityLimit} of {visible.entityIds.size} matches. Refine search or filters to inspect the rest.</div> : null}
      {layoutState === 'fallback' ? <div className="topology-workspace__notice topology-workspace__notice--warning">Automatic layout was unavailable. A deterministic fallback is active.</div> : null}

      <div className="topology-workspace__body">
        <aside className="topology-workspace__rail" aria-label="Topology explorer">
          <label className="topology-search">
            <Search aria-hidden="true" />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Find IP, host, MAC, tag..." aria-label="Search topology" />
            {query ? <button type="button" onClick={() => setQuery('')} aria-label="Clear topology search" title="Clear search"><X aria-hidden="true" /></button> : null}
          </label>

          <details className="topology-filters" open>
            <summary><SlidersHorizontal aria-hidden="true" />Filters{hasFilters ? <span>Active</span> : null}</summary>
            <fieldset>
              <legend>Entity kind</legend>
              {allTopologyKinds.map((kind) => <label key={kind}><input type="checkbox" checked={kinds.has(kind)} onChange={() => setKinds((current) => toggleSetValue(current, kind))} />{kindLabel(kind)}</label>)}
            </fieldset>
            <fieldset>
              <legend>Status</legend>
              {allTopologyStatuses.map((status) => <label key={status}><input type="checkbox" checked={statuses.has(status)} onChange={() => setStatuses((current) => toggleSetValue(current, status))} /><span className={`topology-filter-dot topology-filter-dot--${status}`} aria-hidden="true" />{statusLabel(status)}</label>)}
            </fieldset>
            <fieldset>
              <legend>Relation confidence</legend>
              {allTopologyConfidences.map((confidence) => <label key={confidence}><input type="checkbox" checked={confidences.has(confidence)} onChange={() => setConfidences((current) => toggleSetValue(current, confidence))} />{confidenceLabel(confidence)}</label>)}
            </fieldset>
            <fieldset>
              <legend>Connectivity</legend>
              <div className="topology-filter-segments" role="group" aria-label="Connectivity filter">
                {(['all', 'linked', 'unlinked'] as const).map((value) => <button key={value} type="button" aria-pressed={linkState === value} onClick={() => setLinkState(value)}>{value === 'all' ? 'All' : value === 'linked' ? 'Linked' : 'Unlinked'}</button>)}
              </div>
            </fieldset>
            <button type="button" className="topology-filter-reset" onClick={resetFilters} disabled={!hasFilters}>Reset filters</button>
          </details>

          <div className="topology-outline__heading"><strong>Visible entities</strong><span>{filteredEntities.length}/{model.entities.length}</span></div>
          <ul className="topology-outline" aria-label="Visible topology entities">
            {filteredEntities.length === 0 ? <li className="topology-outline__empty">No entities match these filters.</li> : outlineEntities.map((entity) => (
              <li key={entity.id}>
                <button type="button" aria-pressed={selectedId === entity.id} className={selectedId === entity.id ? 'topology-outline__item topology-outline__item--active' : 'topology-outline__item'} onClick={() => setSelectedId(entity.id)}>
                  <span className={`topology-outline__kind topology-outline__kind--${entity.kind}`} aria-hidden="true">{entity.kind === 'segment' ? <Cable /> : entity.kind === 'node' ? <Network /> : <TerminalSquare />}</span>
                  <span><strong>{entity.label}</strong><small>{entity.subtitle}</small></span>
                  <span className={`topology-filter-dot topology-filter-dot--${entity.status}`} title={entity.status} />
                </button>
              </li>
            ))}
            {filteredEntities.length > topologyOutlineLimit ? <li className="topology-outline__empty">Showing the first {topologyOutlineLimit} matches. Refine the filters to narrow the list.</li> : null}
          </ul>
        </aside>

        <div className="topology-workspace__canvas" role="region" aria-label="Interactive network topology">
          {layoutState === 'running' ? <div className="topology-layout-state" role="status"><span className="refresh-spinner" />Arranging topology...</div> : null}
          <ReactFlow<TopologyFlowNode, TopologyFlowEdge>
            nodes={displayNodes}
            edges={displayEdges}
            colorMode="dark"
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onNodeClick={(_, node) => setSelectedId((current) => current === node.id ? null : node.id)}
            onPaneClick={() => setSelectedId(null)}
            nodesConnectable={false}
            edgesReconnectable={false}
            elementsSelectable
            nodesDraggable
            panOnDrag
            panOnScroll
            zoomOnPinch
            zoomOnScroll
            minZoom={0.12}
            maxZoom={2.25}
            onlyRenderVisibleElements
            fitView
            fitViewOptions={{ padding: 0.18 }}
            attributionPosition="top-right"
          >
            <Background variant={BackgroundVariant.Dots} gap={24} size={1.2} color="#344039" />
            <MiniMap<TopologyFlowNode> pannable zoomable nodeColor={miniMapColor} nodeStrokeColor="#101512" nodeStrokeWidth={3} maskColor="rgba(10, 14, 12, 0.72)" ariaLabel="Topology minimap" />
            <Controls position="bottom-left" showInteractive={false} />
          </ReactFlow>
        </div>

        <aside className="topology-inspector" aria-label="Selected topology entity">
          {selectedEntity ? (
            <>
              <div className="topology-inspector__heading">
                <span className={`topology-inspector__glyph topology-inspector__glyph--${selectedEntity.kind}`} aria-hidden="true">{selectedEntity.kind === 'segment' ? <Cable /> : selectedEntity.kind === 'node' ? <Network /> : <TerminalSquare />}</span>
                <div><span>{kindLabel(selectedEntity.kind).slice(0, -1)}</span><h3>{selectedEntity.label}</h3></div>
                <button type="button" className="icon-button icon-button--small" onClick={() => setSelectedId(null)} aria-label="Close topology inspector" title="Close"><X aria-hidden="true" /></button>
              </div>
              <div className={`topology-inspector__state topology-inspector__state--${selectedEntity.status}`}><span aria-hidden="true" />{selectedEntity.status}</div>
              <dl>{entityDetails(selectedEntity).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
              <div className="topology-inspector__actions">
                <button type="button" className="secondary-button" onClick={() => void fitView({ nodes: [{ id: selectedEntity.id }], padding: 0.7, duration: 280, maxZoom: 1.25 })}><LocateFixed aria-hidden="true" />Focus</button>
                {(selectedEntity.kind === 'device' ? onEditDevice : selectedEntity.kind === 'node' ? onEditNetworkNode : onEditNetworkSegment) ? <button type="button" className="secondary-button" onClick={editSelected}><Pencil aria-hidden="true" />Edit</button> : null}
                {panelLink ? <a className="secondary-button" href={panelLink} target="_blank" rel="noreferrer"><ExternalLink aria-hidden="true" />Panel</a> : null}
                {selectedEntity.kind === 'device' && onOpenSSH ? <button type="button" className="secondary-button" onClick={() => onOpenSSH(selectedEntity.raw as Device)}><TerminalSquare aria-hidden="true" />SSH</button> : null}
                {selectedEntity.kind === 'device' && onWake && (selectedEntity.raw as Device).macAddress ? <button type="button" className="secondary-button" onClick={() => onWake(selectedEntity.raw as Device)}><Power aria-hidden="true" />Wake</button> : null}
              </div>
              <div className="topology-inspector__relations">
                <div><strong>Connected relations</strong><span>{selectedLinks.length}</span></div>
                {selectedLinks.length === 0 ? <p>No explicit relation connects this entity.</p> : <ul>{selectedLinks.map((link) => {
                  const peerId = link.source === selectedEntity.id ? link.target : link.source
                  const peer = model.entities.find((entity) => entity.id === peerId)
                  return <li key={link.id}><button type="button" onClick={() => setSelectedId(peerId)}><span>{link.label}</span><strong>{peer?.label ?? peerId}</strong><small>{link.confidence}</small></button></li>
                })}</ul>}
              </div>
            </>
          ) : (
            <div className="topology-inspector__empty"><Network aria-hidden="true" /><strong>Select an entity</strong><span>Inspect its network facts and highlight every direct relation.</span></div>
          )}
        </aside>
      </div>
    </div>
  )
}

export default function TopologyGraph(props: TopologyGraphProps) {
  return <ReactFlowProvider><TopologyWorkspace {...props} /></ReactFlowProvider>
}
