import { memo } from 'react'
import { Cable, Router, Server } from 'lucide-react'
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import type { TopologyDirection, TopologyEntity } from './topology-model'

export type TopologyNodeData = {
  entity: TopologyEntity
  direction: TopologyDirection
  [key: string]: unknown
}

export type TopologyFlowNode = Node<TopologyNodeData, 'topologyEntity'>

function kindLabel(kind: TopologyEntity['kind']) {
  if (kind === 'segment') {
    return 'Segment'
  }
  if (kind === 'node') {
    return 'Network node'
  }
  return 'Device'
}

function TopologyEntityNode({ data, selected }: NodeProps<TopologyFlowNode>) {
  const { entity, direction } = data
  const Icon = entity.kind === 'segment' ? Cable : entity.kind === 'node' ? Router : Server
  const targetPosition = direction === 'RIGHT' ? Position.Left : Position.Top
  const sourcePosition = direction === 'RIGHT' ? Position.Right : Position.Bottom

  return (
    <div
      className={`topology-entity topology-entity--${entity.kind} topology-entity--${entity.status}${selected ? ' topology-entity--selected' : ''}`}
      title={`${entity.label}: ${entity.subtitle} - ${entity.detail}`}
    >
      <Handle type="target" position={targetPosition} className="topology-entity__handle" isConnectable={false} />
      <span className="topology-entity__rail" aria-hidden="true" />
      <div className="topology-entity__icon" aria-hidden="true"><Icon /></div>
      <div className="topology-entity__copy">
        <span className="topology-entity__kind">{kindLabel(entity.kind)}</span>
        <strong>{entity.label}</strong>
        <span className="topology-entity__subtitle">{entity.subtitle}</span>
      </div>
      <div className="topology-entity__footer">
        <span className="topology-entity__status"><span aria-hidden="true" />{entity.status}</span>
        <span>{entity.connectionCount} {entity.connectionCount === 1 ? 'link' : 'links'}</span>
      </div>
      <Handle type="source" position={sourcePosition} className="topology-entity__handle" isConnectable={false} />
    </div>
  )
}

export default memo(TopologyEntityNode)
