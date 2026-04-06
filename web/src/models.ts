export type Device = {
  id: string
  name: string
  hostname: string
  role: string
  deviceType: string
  ipAddress: string
  macAddress: string
  networkSegment: string
  status: string
  tags: string[]
  metadata?: Record<string, string>
}

export type NetworkNode = {
  id: string
  name: string
  nodeType: string
  managementIp: string
  macAddress: string
  vendor: string
  model: string
  status: string
  tags: string[]
  metadata?: Record<string, string>
}

export type NetworkSegment = {
  id: string
  name: string
  segmentType: string
  cidr: string
  vlanId: number
  gatewayIp: string
  dnsDomain: string
  metadata?: Record<string, string>
}

export type Relation = {
  id: string
  sourceKind: string
  sourceId: string
  targetKind: string
  targetId: string
  relationType: string
  confidence: string
}

export type Action = {
  id: string
  deviceId: string
  actionType: string
  status: string
  resultSummary: string
  metadata?: Record<string, string>
  startedAt: string
}

export type SSHCredential = {
  deviceId: string
  username: string
  hasPassword: boolean
  keyVersion: number
  sshPort: string
}

export type InventorySnapshot = {
  devices: Device[]
  networkNodes: NetworkNode[]
  networkSegments: NetworkSegment[]
  relations: Relation[]
  actions: Action[]
}

export type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; data: InventorySnapshot }

export type DeviceDraft = {
  name: string
  hostname: string
  role: string
  deviceType: string
  ipAddress: string
  macAddress: string
  networkSegment: string
  tags: string[]
}

export type NetworkNodeDraft = {
  name: string
  nodeType: string
  managementIp: string
  vendor: string
  model: string
}

export type NetworkSegmentDraft = {
  name: string
  segmentType: string
  cidr: string
  vlanId: string
  gatewayIp: string
  dnsDomain: string
}

export type SSHCredentialDraft = {
  username: string
  password: string
  sshPort: string
}

export type ToastState = {
  kind: 'error' | 'success'
  message: string
} | null

export const initialDeviceDraft: DeviceDraft = {
  name: '',
  hostname: '',
  role: '',
  deviceType: '',
  ipAddress: '',
  macAddress: '',
  networkSegment: '',
  tags: [],
}

export const initialSSHCredentialDraft: SSHCredentialDraft = {
  username: '',
  password: '',
  sshPort: '22',
}

export const initialNetworkNodeDraft: NetworkNodeDraft = {
  name: '',
  nodeType: '',
  managementIp: '',
  vendor: '',
  model: '',
}

export const initialNetworkSegmentDraft: NetworkSegmentDraft = {
  name: '',
  segmentType: '',
  cidr: '',
  vlanId: '',
  gatewayIp: '',
  dnsDomain: '',
}

export const deviceTagOptions = [
  'desktop',
  'laptop',
  'server',
  'nas',
  'raspberry-pi',
  'router',
  'switch',
  'access-point',
  'iot',
  'printer',
]

export const networkNodeTypeOptions = [
  'router',
  'switch',
  'access-point',
  'gateway',
  'firewall',
  'modem',
  'controller',
  'bridge',
]
