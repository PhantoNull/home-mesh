import { memo } from 'react'
import { Cable, HardDrive, Laptop, Monitor, Network, Printer, Router, Server, Smartphone, Tv, Wifi } from 'lucide-react'
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import type { Device, NetworkNode, NetworkSegment } from './models'
import type { TopologyDirection, TopologyEntity } from './topology-model'

export type TopologyNodeData = {
  entity: TopologyEntity
  direction: TopologyDirection
  [key: string]: unknown
}

export type TopologyFlowNode = Node<TopologyNodeData, 'topologyEntity'>

function entityPresentation(entity: TopologyEntity) {
  if (entity.kind === 'segment') {
    const segment = entity.raw as NetworkSegment
    return {
      Icon: Network,
      kind: segment.vlanId ? `VLAN ${segment.vlanId}` : segment.segmentType || 'Network segment',
      badge: segment.gatewayIp ? `GW ${segment.gatewayIp}` : 'No gateway',
    }
  }
  if (entity.kind === 'node') {
    const node = entity.raw as NetworkNode
    const type = node.nodeType.toLowerCase()
    return {
      Icon: type.includes('router') || type.includes('gateway') || type.includes('firewall')
        ? Router
        : type.includes('access-point') || type.includes('wifi') || type === 'ap'
          ? Wifi
          : type.includes('switch')
            ? Cable
            : Network,
      kind: node.nodeType || 'Network node',
      badge: node.model || node.vendor || 'Infrastructure',
    }
  }
  const device = entity.raw as Device
  const type = `${device.deviceType} ${device.role}`.toLowerCase()
  const Icon = type.includes('nas') || type.includes('storage')
    ? HardDrive
    : type.includes('laptop') || type.includes('notebook')
      ? Laptop
      : type.includes('phone') || type.includes('mobile')
        ? Smartphone
        : type.includes('printer')
          ? Printer
          : type.includes('tv') || type.includes('television')
            ? Tv
            : type.includes('server') || type.includes('hypervisor')
              ? Server
              : Monitor
  return {
    Icon,
    kind: device.deviceType || device.role || 'Device',
    badge: device.hostname || device.ipAddress || 'Endpoint',
  }
}

function TopologyEntityNode({ data, selected }: NodeProps<TopologyFlowNode>) {
  const { entity, direction } = data
  const { Icon, kind, badge } = entityPresentation(entity)
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
        <span className="topology-entity__kind">{kind}</span>
        <strong>{entity.label}</strong>
        <span className="topology-entity__subtitle">{entity.subtitle}</span>
      </div>
      <div className="topology-entity__footer">
        <span className="topology-entity__status"><span aria-hidden="true" />{entity.status}</span>
        <span title={badge}>{entity.connectionCount} {entity.connectionCount === 1 ? 'link' : 'links'}</span>
      </div>
      <Handle type="source" position={sourcePosition} className="topology-entity__handle" isConnectable={false} />
    </div>
  )
}

export default memo(TopologyEntityNode)
