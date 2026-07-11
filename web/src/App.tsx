import { type KeyboardEvent as ReactKeyboardEvent, type ReactNode, useEffect, useRef, useState } from 'react'
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronUp,
  Columns3,
  ExternalLink,
  History,
  List,
  LogOut,
  Network,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  ScanLine,
  SquareTerminal,
  Trash2,
  UserCircle,
} from 'lucide-react'
import DraggableModal from './DraggableModal'
import RelationEditor, { type RelationDraft } from './RelationEditor'
import { parseSSHServerMessage } from './ssh-events'
import {
  parseDiscoveryCompleteEvent,
  parseDiscoveryErrorEvent,
  parseDiscoveryHostEvent,
} from './discovery-events'
import {
  getSafePanelLink,
  moveItemByOffset,
  normalizePanelURL,
  panelURLValidationError,
  parseBulkRefreshResponse,
  resolveSSHCapability,
  statusClassName,
  topologyEntityKey,
  truncateTopologyLabel,
} from './frontend-utils'
import {
  type Action,
  type DiscoveryCapabilities,
  type DiscoveryHostMatch,
  type DiscoveryScanResult,
  type Device,
  type DeviceDraft,
  type InventorySnapshot,
  type LoadState,
  type NetworkNode,
  type NetworkNodeDraft,
  type NetworkSegment,
  type NetworkSegmentDraft,
  type Relation,
  type SSHCredential,
  type SSHCredentialDraft,
  type ToastState,
  deviceTagOptions,
  initialDeviceDraft,
  initialNetworkNodeDraft,
  initialNetworkSegmentDraft,
  initialSSHCredentialDraft,
  networkNodeTypeOptions,
} from './models'

type MetricCardProps = {
  title: string
  value: string
  accent: 'blue' | 'green' | 'amber'
}

type DeviceFormProps = {
  draft: DeviceDraft
  submitState: 'idle' | 'saving'
  errorMessage: string | null
  submitLabel: string
  onChange: (field: Exclude<keyof DeviceDraft, 'tags'>, value: string) => void
  onToggleTag: (tag: string) => void
  onSubmit: () => Promise<void>
}

type NetworkNodeFormProps = {
  draft: NetworkNodeDraft
  submitState: 'idle' | 'saving'
  errorMessage: string | null
  submitLabel: string
  onChange: (field: keyof NetworkNodeDraft, value: string) => void
  onSubmit: () => Promise<void>
}

type NetworkSegmentFormProps = {
  draft: NetworkSegmentDraft
  submitState: 'idle' | 'saving'
  errorMessage: string | null
  submitLabel: string
  onChange: (field: keyof NetworkSegmentDraft, value: string) => void
  onSubmit: () => Promise<void>
}

type SSHCredentialFormProps = {
  draft: SSHCredentialDraft
  submitState: 'idle' | 'loading' | 'saving'
  errorMessage: string | null
  hasStoredPassword: boolean
  onChange: (field: keyof SSHCredentialDraft, value: string) => void
  onSubmit: () => Promise<void>
  onCancel: () => void
}

type SSHTerminalPaneProps = {
  deviceId: string
  enabled: boolean
  unavailableReason?: string | null
  sessionKey: number
  onConnectionState: (message: string) => void
  onReconnect: () => void
}

type EndpointListProps = {
  devices: Device[]
  actionState: Record<string, string>
  sshConfigured: Record<string, boolean>
  refreshingItems: Record<string, boolean>
  onEdit: (device: Device) => void
  onOpenSSH: (device: Device) => Promise<void>
  onWake: (device: Device) => Promise<void>
  onDelete: (device: Device) => Promise<void>
  onReorder: (items: Device[]) => Promise<void>
}

type CollapsibleSectionProps = {
  label?: string
  title: string
  defaultCollapsed?: boolean
  children: ReactNode
}

type AuthPanelProps = {
  submitState: 'idle' | 'submitting'
  errorMessage: string | null
  draft: { username: string; password: string }
  onChange: (field: 'username' | 'password', value: string) => void
  onSubmit: () => Promise<void>
}

function moveByIds<T extends { id: string }>(items: T[], fromId: string, toId: string): T[] {
  const fromIndex = items.findIndex((item) => item.id === fromId)
  const toIndex = items.findIndex((item) => item.id === toId)
  if (fromIndex === -1 || toIndex === -1 || fromIndex === toIndex) {
    return items
  }

  const next = [...items]
  const [moved] = next.splice(fromIndex, 1)
  next.splice(toIndex, 0, moved)
  return next
}

function writeDragID(dataTransfer: DataTransfer, kind: string, id: string) {
  dataTransfer.effectAllowed = 'move'
  dataTransfer.setData('text/plain', id)
  dataTransfer.setData(`text/home-mesh-${kind}`, id)
}

function readDragID(dataTransfer: DataTransfer, kind: string): string {
  return dataTransfer.getData(`text/home-mesh-${kind}`) || dataTransfer.getData('text/plain')
}

function isValidCIDR(value: string): boolean {
  const trimmed = value.trim()
  const match = /^(\d{1,3})(\.\d{1,3}){3}\/(\d{1,2})$/.exec(trimmed)
  if (!match) {
    return false
  }

  const [address, prefixText] = trimmed.split('/')
  const octets = address.split('.').map((part) => Number.parseInt(part, 10))
  const prefix = Number.parseInt(prefixText, 10)

  if (octets.length !== 4 || octets.some((octet) => Number.isNaN(octet) || octet < 0 || octet > 255)) {
    return false
  }

  return !(Number.isNaN(prefix) || prefix < 0 || prefix > 32)
}

function createRelationID(): string {
  if (typeof crypto.randomUUID === 'function') {
    return `rel-${crypto.randomUUID()}`
  }
  const entropy = crypto.getRandomValues(new Uint32Array(2))
  return `rel-${Date.now().toString(36)}-${entropy[0].toString(36)}${entropy[1].toString(36)}`
}

function updateDeviceInSnapshot(snapshot: InventorySnapshot, device: Device): InventorySnapshot {
  return {
    ...snapshot,
    devices: snapshot.devices.map((current) => (current.id === device.id ? device : current)),
  }
}

function updateNetworkNodeInSnapshot(snapshot: InventorySnapshot, node: NetworkNode): InventorySnapshot {
  return {
    ...snapshot,
    networkNodes: snapshot.networkNodes.map((current) => (current.id === node.id ? node : current)),
  }
}

function MetricCard({ title, value, accent }: MetricCardProps) {
  return (
    <article className={`metric-card metric-card--${accent}`}>
      <p className="metric-card__title">{title}</p>
      <strong className="metric-card__value">{value}</strong>
    </article>
  )
}

function AuthPanel({ submitState, errorMessage, draft, onChange, onSubmit }: AuthPanelProps) {
  return (
    <section className="feedback-panel auth-panel">
      <p className="section-label">Authentication</p>
      <h2>Sign in to Home Mesh</h2>
      <form
        className="device-form"
        autoComplete="on"
        onSubmit={(event) => {
          event.preventDefault()
          void onSubmit()
        }}
      >
        {errorMessage ? <div className="inline-error" role="alert">{errorMessage}</div> : null}
        <div className="form-grid">
          <label className="form-field">
            <span>Username</span>
            <input
              value={draft.username}
              onChange={(event) => onChange('username', event.target.value)}
              autoComplete="username"
              name="username"
              required
            />
          </label>
          <label className="form-field">
            <span>Password</span>
            <input
              type="password"
              value={draft.password}
              onChange={(event) => onChange('password', event.target.value)}
              autoComplete="current-password"
              name="password"
              required
            />
          </label>
        </div>
        <div className="form-actions">
          <button type="submit" className="action-button" disabled={submitState === 'submitting'}>
            {submitState === 'submitting' ? 'Signing in...' : 'Sign in'}
          </button>
        </div>
      </form>
    </section>
  )
}

function CollapsibleSection({ label, title, defaultCollapsed = false, children }: CollapsibleSectionProps) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed)

  return (
    <section className="collapsible-section">
      <div className="collapsible-section__header">
        <div>
          {label ? <p className="section-label">{label}</p> : null}
          <h3 className="collapsible-section__title">{title}</h3>
        </div>
        <button
          type="button"
          className="icon-button collapsible-section__toggle"
          onClick={() => setCollapsed((current) => !current)}
          aria-label={collapsed ? `Expand ${title}` : `Collapse ${title}`}
          title={collapsed ? `Expand ${title}` : `Collapse ${title}`}
        >
          {collapsed ? <ChevronDown aria-hidden="true" /> : <ChevronUp aria-hidden="true" />}
        </button>
      </div>
      {!collapsed ? <div className="collapsible-section__content">{children}</div> : null}
    </section>
  )
}

function DeviceForm({ draft, submitState, errorMessage, submitLabel, onChange, onToggleTag, onSubmit }: DeviceFormProps) {
  return (
    <form
      className="device-form"
      onSubmit={(event) => {
        event.preventDefault()
        void onSubmit()
      }}
    >
      {errorMessage ? <div className="inline-error" role="alert">{errorMessage}</div> : null}

      <div className="form-grid">
        <label className="form-field">
          <span>Name</span>
          <input value={draft.name} onChange={(event) => onChange('name', event.target.value)} />
        </label>
        <label className="form-field">
          <span>Hostname</span>
          <input value={draft.hostname} onChange={(event) => onChange('hostname', event.target.value)} />
        </label>
        <label className="form-field">
          <span>Role</span>
          <input value={draft.role} onChange={(event) => onChange('role', event.target.value)} />
        </label>
        <label className="form-field">
          <span>Type</span>
          <input value={draft.deviceType} onChange={(event) => onChange('deviceType', event.target.value)} />
        </label>
        <label className="form-field">
          <span>IP address</span>
          <input value={draft.ipAddress} onChange={(event) => onChange('ipAddress', event.target.value)} />
        </label>
        <label className="form-field">
          <span>MAC address</span>
          <input value={draft.macAddress} onChange={(event) => onChange('macAddress', event.target.value)} />
        </label>
        <label className="form-field form-field--wide">
          <span>Panel link</span>
          <input type="url" inputMode="url" value={draft.panelLink} onChange={(event) => onChange('panelLink', event.target.value)} placeholder="https://device.local" />
        </label>
        <label className="form-field">
          <span>Segment id</span>
          <input value={draft.networkSegment} onChange={(event) => onChange('networkSegment', event.target.value)} />
        </label>
        <label className="form-field form-field--wide">
          <span>Tags</span>
          <div className="tag-selector">
            {deviceTagOptions.map((tag) => {
              const selected = draft.tags.includes(tag)

              return (
                <button
                  key={tag}
                  type="button"
                  className={selected ? 'tag-option tag-option--selected' : 'tag-option'}
                  onClick={() => onToggleTag(tag)}
                  aria-pressed={selected}
                >
                  {tag}
                </button>
              )
            })}
          </div>
        </label>
      </div>
      <div className="form-actions">
        <button type="submit" className="action-button" disabled={submitState === 'saving'}>
          {submitState === 'saving' ? 'Saving...' : submitLabel}
        </button>
      </div>
    </form>
  )
}

function NetworkNodeForm({ draft, submitState, errorMessage, submitLabel, onChange, onSubmit }: NetworkNodeFormProps) {
  return (
    <form
      className="device-form"
      onSubmit={(event) => {
        event.preventDefault()
        void onSubmit()
      }}
    >
      {errorMessage ? <div className="inline-error" role="alert">{errorMessage}</div> : null}

      <div className="form-grid">
        <label className="form-field">
          <span>Name</span>
          <input value={draft.name} onChange={(event) => onChange('name', event.target.value)} />
        </label>
        <label className="form-field">
          <span>Type</span>
          <select value={draft.nodeType} onChange={(event) => onChange('nodeType', event.target.value)}>
            <option value="">Select type</option>
            {networkNodeTypeOptions.map((nodeType) => (
              <option key={nodeType} value={nodeType}>
                {nodeType}
              </option>
            ))}
          </select>
        </label>
        <label className="form-field">
          <span>Management IP</span>
          <input value={draft.managementIp} onChange={(event) => onChange('managementIp', event.target.value)} />
        </label>
        <label className="form-field">
          <span>Vendor</span>
          <input value={draft.vendor} onChange={(event) => onChange('vendor', event.target.value)} />
        </label>
        <label className="form-field">
          <span>Model</span>
          <input value={draft.model} onChange={(event) => onChange('model', event.target.value)} />
        </label>
        <label className="form-field form-field--wide">
          <span>Panel link</span>
          <input type="url" inputMode="url" value={draft.panelLink} onChange={(event) => onChange('panelLink', event.target.value)} placeholder="https://router.local" />
        </label>
      </div>
      <div className="form-actions">
        <button type="submit" className="action-button" disabled={submitState === 'saving'}>
          {submitState === 'saving' ? 'Saving...' : submitLabel}
        </button>
      </div>
    </form>
  )
}

function NetworkSegmentForm({ draft, submitState, errorMessage, submitLabel, onChange, onSubmit }: NetworkSegmentFormProps) {
  return (
    <form
      className="device-form"
      onSubmit={(event) => {
        event.preventDefault()
        void onSubmit()
      }}
    >
      {errorMessage ? <div className="inline-error" role="alert">{errorMessage}</div> : null}

      <div className="form-grid">
        <label className="form-field">
          <span>Name</span>
          <input value={draft.name} onChange={(event) => onChange('name', event.target.value)} />
        </label>
        <label className="form-field">
          <span>Type</span>
          <input value={draft.segmentType} onChange={(event) => onChange('segmentType', event.target.value)} />
        </label>
        <label className="form-field">
          <span>CIDR</span>
          <input value={draft.cidr} onChange={(event) => onChange('cidr', event.target.value)} />
        </label>
        <label className="form-field">
          <span>VLAN ID</span>
          <input value={draft.vlanId} onChange={(event) => onChange('vlanId', event.target.value)} />
        </label>
        <label className="form-field">
          <span>Gateway IP</span>
          <input value={draft.gatewayIp} onChange={(event) => onChange('gatewayIp', event.target.value)} />
        </label>
        <label className="form-field">
          <span>DNS domain</span>
          <input value={draft.dnsDomain} onChange={(event) => onChange('dnsDomain', event.target.value)} />
        </label>
      </div>
      <div className="form-actions">
        <button type="submit" className="action-button" disabled={submitState === 'saving'}>
          {submitState === 'saving' ? 'Saving...' : submitLabel}
        </button>
      </div>
    </form>
  )
}

function SSHCredentialForm({
  draft,
  submitState,
  errorMessage,
  hasStoredPassword,
  onChange,
  onSubmit,
  onCancel,
}: SSHCredentialFormProps) {
  return (
    <form
      className="device-form"
      onSubmit={(event) => {
        event.preventDefault()
        void onSubmit()
      }}
    >
      {errorMessage ? <div className="inline-error" role="alert">{errorMessage}</div> : null}

      <div className="form-grid">
        <label className="form-field">
          <span>SSH username</span>
          <input value={draft.username} onChange={(event) => onChange('username', event.target.value)} />
        </label>
        <label className="form-field">
          <span>SSH password</span>
          <input
            type="password"
            value={draft.password}
            onChange={(event) => onChange('password', event.target.value)}
            placeholder={hasStoredPassword ? 'Enter a new password to replace the stored one' : 'Enter password'}
          />
        </label>
        <label className="form-field">
          <span>SSH port</span>
          <input value={draft.sshPort} onChange={(event) => onChange('sshPort', event.target.value)} placeholder="22" />
        </label>
      </div>
      <div className="form-note">
        Credentials are stored encrypted server-side. {hasStoredPassword ? 'A password is already stored for this device.' : 'No password is stored yet.'}
      </div>
      <div className="form-actions">
        <button type="button" className="secondary-button" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="action-button" disabled={submitState === 'saving' || submitState === 'loading'}>
          {submitState === 'saving' ? 'Saving...' : 'Save SSH credentials'}
        </button>
      </div>
    </form>
  )
}

function SSHTerminalPane({ deviceId, enabled, unavailableReason, sessionKey, onConnectionState, onReconnect }: SSHTerminalPaneProps) {
  const hostRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!enabled || !hostRef.current) {
      onConnectionState(unavailableReason ? 'SSH unavailable' : 'Credentials required')
      return
    }

    let cancelled = false
    let observer: ResizeObserver | null = null
    let heartbeatId: number | null = null
    let cleanup: (() => void) | null = null

    void (async () => {
      try {
        const [{ Terminal }, { FitAddon }] = await Promise.all([
          import('@xterm/xterm'),
          import('@xterm/addon-fit'),
          import('@xterm/xterm/css/xterm.css'),
        ])
        if (cancelled || !hostRef.current) {
          return
        }

        const terminal = new Terminal({
          cursorBlink: true,
          convertEol: true,
          fontSize: 14,
          theme: {
            background: '#060b16',
            foreground: '#cfe3ff',
          },
        })
        const fitAddon = new FitAddon()
        terminal.loadAddon(fitAddon)
        terminal.open(hostRef.current)
        fitAddon.fit()
        terminal.writeln('Connecting to SSH session...')
        onConnectionState('Connecting...')

        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
        const socket = new WebSocket(`${protocol}://${window.location.host}/api/devices/${deviceId}/ssh-terminal`)

        const resize = () => {
          fitAddon.fit()
          socket.send(
            JSON.stringify({
              type: 'resize',
              cols: terminal.cols,
              rows: terminal.rows,
            }),
          )
        }

        socket.onopen = () => {
          resize()
          terminal.focus()
          heartbeatId = window.setInterval(() => {
            if (socket.readyState === WebSocket.OPEN) {
              socket.send(JSON.stringify({ type: 'ping' }))
            }
          }, 25000)
        }

        socket.onmessage = (event) => {
          let message
          try {
            message = parseSSHServerMessage(event.data)
          } catch (error) {
            const text = error instanceof Error ? error.message : 'SSH terminal received an invalid message.'
            onConnectionState('Protocol error')
            terminal.writeln(`\r\n[error] ${text}`)
            socket.close(1002, 'invalid server message')
            return
          }
          switch (message.type) {
            case 'output':
              terminal.write(message.data ?? '')
              break
            case 'error':
              onConnectionState(message.data ?? 'SSH error')
              terminal.writeln(`\r\n[error] ${message.data ?? 'Unknown SSH error'}`)
              break
            case 'status':
              if (message.data === 'connected') {
                onConnectionState('Connected')
                terminal.writeln('\r\n[connected]')
              } else if (message.data === 'closed') {
                onConnectionState('Session closed')
                terminal.writeln('\r\n[session closed]')
              }
              break
            case 'pong':
              break
          }
        }

        socket.onerror = () => {
          onConnectionState('Connection failed')
          terminal.writeln('\r\n[error] SSH terminal connection failed.')
        }

        socket.onclose = () => {
          onConnectionState('Disconnected')
        }

        terminal.onData((data) => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: 'input', data }))
          }
        })

        observer = new ResizeObserver(() => {
          if (socket.readyState === WebSocket.OPEN) {
            resize()
          }
        })
        observer.observe(hostRef.current)

        cleanup = () => {
          observer?.disconnect()
          if (heartbeatId !== null) {
            window.clearInterval(heartbeatId)
          }
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: 'close' }))
          }
          onConnectionState('Disconnected')
          socket.close()
          terminal.dispose()
        }
      } catch (error) {
        if (!cancelled) {
          onConnectionState('Connection failed')
          console.error(error)
        }
      }
    })()

    return () => {
      cancelled = true
      cleanup?.()
    }
  }, [deviceId, enabled, onConnectionState, sessionKey, unavailableReason])

  if (!enabled) {
    return (
      <section className="ssh-console">
        <div className="modal-panel__heading">
          <p className="section-label">SSH console</p>
          <h2>{unavailableReason ? 'SSH unavailable' : 'Credentials required'}</h2>
        </div>
        <div className={unavailableReason ? 'inline-error' : 'form-note'} role={unavailableReason ? 'alert' : undefined}>
          {unavailableReason ?? 'Save SSH credentials for this device to open an interactive shell.'}
        </div>
      </section>
    )
  }

  return (
    <section className="ssh-console">
      <div className="panel-title-row">
        <div className="modal-panel__heading">
          <p className="section-label">SSH console</p>
          <h2>Connect</h2>
        </div>
        <button type="button" className="secondary-button" onClick={onReconnect}>
          Reconnect
        </button>
      </div>
      <div ref={hostRef} className="ssh-terminal-host" />
    </section>
  )
}

function EndpointList({ devices, actionState, sshConfigured, refreshingItems, onEdit, onOpenSSH, onWake, onDelete, onReorder }: EndpointListProps) {
  const [previewDevices, setPreviewDevices] = useState<Device[]>(devices ?? [])
  const dragDeviceIdRef = useRef<string | null>(null)
  const previewDevicesRef = useRef<Device[]>(devices ?? [])

  useEffect(() => {
    setPreviewDevices(devices ?? [])
    previewDevicesRef.current = devices ?? []
  }, [devices])

  if (!devices || devices.length === 0) {
    return <div className="empty-state">Empty</div>
  }

  return (
    <div className="inventory-list inventory-list--cards">
      {(previewDevices ?? []).map((device, index) => {
        const canWake = Boolean(device.macAddress) && device.status !== 'online'
        const busy =
          actionState[device.id] === 'running' ||
          actionState[device.id] === 'deleting' ||
          actionState[device.id] === 'ssh'
        const panelLink = getSafePanelLink(device.metadata)

        return (
          <article
            key={device.id}
            className="inventory-row inventory-row--draggable"
            draggable
            onDragStart={(event) => {
              dragDeviceIdRef.current = device.id
              writeDragID(event.dataTransfer, 'device', device.id)
            }}
            onDragEnd={() => {
              dragDeviceIdRef.current = null
              setPreviewDevices(devices ?? [])
            }}
            onDragOver={(event) => {
              event.preventDefault()
              const fromId = dragDeviceIdRef.current
              if (!fromId || fromId === device.id) {
                return
              }

              setPreviewDevices((current) => {
                const next = moveByIds(current, fromId, device.id)
                previewDevicesRef.current = next
                return next
              })
            }}
            onDrop={(event) => {
              event.preventDefault()
              const fromId = readDragID(event.dataTransfer, 'device')
              if (fromId) {
                dragDeviceIdRef.current = null
                if (JSON.stringify(previewDevicesRef.current.map((item) => item.id)) !== JSON.stringify((devices ?? []).map((item) => item.id))) {
                  void onReorder(previewDevicesRef.current)
                }
              }
            }}
          >
            <div className="inventory-row__body">
              <div className="inventory-row__header">
                <strong>{device.name}</strong>
                <div className="inventory-row__header-actions">
                  <button
                    type="button"
                    className="icon-button icon-button--small"
                    onClick={() => void onReorder(moveItemByOffset(previewDevices, index, -1))}
                    disabled={busy || index === 0}
                    aria-label={`Move ${device.name} up`}
                    title="Move up"
                  >
                    <ArrowUp aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    className="icon-button icon-button--small"
                    onClick={() => void onReorder(moveItemByOffset(previewDevices, index, 1))}
                    disabled={busy || index === previewDevices.length - 1}
                    aria-label={`Move ${device.name} down`}
                    title="Move down"
                  >
                    <ArrowDown aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    className="icon-button icon-button--small"
                    onClick={() => onEdit(device)}
                    disabled={busy}
                    aria-label={`Edit ${device.name}`}
                    title={`Edit ${device.name}`}
                  >
                    <Pencil aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    className="icon-danger-button"
                    onClick={() => void onDelete(device)}
                    disabled={busy}
                    aria-label={`Delete ${device.name}`}
                    title={`Delete ${device.name}`}
                  >
                    {actionState[device.id] === 'deleting' ? <span className="refresh-spinner" aria-hidden="true" /> : <Trash2 aria-hidden="true" />}
                  </button>
                  {refreshingItems[device.id] ? <span className="refresh-spinner" aria-label="Refreshing" title="Refreshing" /> : null}
                  <span className={`status-pill status-pill--${statusClassName(device.status)}`}>{device.status}</span>
                </div>
              </div>
              <p className="inventory-row__meta">
                <span className="inventory-row__meta-label">DNS</span>
                <span className="inventory-row__meta-value">{device.hostname || 'No hostname'}</span>
              </p>
              <p className="inventory-row__meta">
                <span className="inventory-row__meta-label">IP</span>
                <span className="inventory-row__meta-value">{device.ipAddress || 'No IP address'}</span>
              </p>
              <p className="inventory-row__meta">
                <span className="inventory-row__meta-label">MAC</span>
                <span className="inventory-row__meta-value">{device.macAddress || 'Mac not resolved yet'}</span>
              </p>
            </div>
            <div className="inventory-row__actions inventory-row__actions--device">
              {panelLink ? (
                <a className="action-button panel-button" href={panelLink} target="_blank" rel="noreferrer">
                  <span className="panel-button__icon" aria-hidden="true">
                    <ExternalLink aria-hidden="true" />
                  </span>
                  <span>Panel</span>
                </a>
              ) : null}
              <button
                type="button"
                className={sshConfigured[device.id] ? 'action-button ssh-button ssh-button--configured' : 'action-button ssh-button'}
                onClick={() => void onOpenSSH(device)}
                disabled={busy}
              >
                <span className="ssh-button__icon" aria-hidden="true">
                  <SquareTerminal aria-hidden="true" />
                </span>
                <span>{actionState[device.id] === 'ssh' ? 'Loading...' : 'SSH'}</span>
              </button>
              {canWake ? (
                <button
                  type="button"
                  className="action-button wake-button"
                  onClick={() => void onWake(device)}
                  disabled={busy}
                >
                  <span className="wake-button__icon" aria-hidden="true">
                    <Power aria-hidden="true" />
                  </span>
                  <span>{actionState[device.id] === 'running' ? 'Sending...' : 'WoL'}</span>
                </button>
              ) : null}
            </div>
            <div className="inventory-row__tags inventory-row__tags--device">
              {(device.tags ?? []).map((tag) => (
                <span key={tag} className="tag-pill">
                  {tag}
                </span>
              ))}
            </div>
          </article>
        )
      })}
    </div>
  )
}

function InfrastructureList({
  nodes,
  onEdit,
  onDelete,
  actionState,
  refreshingItems,
  onReorder,
}: {
  nodes: NetworkNode[]
  onEdit: (node: NetworkNode) => void
  onDelete: (node: NetworkNode) => Promise<void>
  actionState: Record<string, string>
  refreshingItems: Record<string, boolean>
  onReorder: (items: NetworkNode[]) => Promise<void>
}) {
  const [previewNodes, setPreviewNodes] = useState<NetworkNode[]>(nodes ?? [])
  const dragNodeIdRef = useRef<string | null>(null)
  const previewNodesRef = useRef<NetworkNode[]>(nodes ?? [])

  useEffect(() => {
    setPreviewNodes(nodes ?? [])
    previewNodesRef.current = nodes ?? []
  }, [nodes])

  if (!nodes || nodes.length === 0) {
    return <div className="empty-state">Empty</div>
  }

  return (
    <div className="inventory-list inventory-list--cards">
      {(previewNodes ?? []).map((node, index) => {
        const panelLink = getSafePanelLink(node.metadata)

        return (
          <article
          key={node.id}
          className="inventory-row inventory-row--draggable"
          draggable
          onDragStart={(event) => {
            dragNodeIdRef.current = node.id
            writeDragID(event.dataTransfer, 'node', node.id)
          }}
          onDragEnd={() => {
            dragNodeIdRef.current = null
            setPreviewNodes(nodes ?? [])
          }}
          onDragOver={(event) => {
            event.preventDefault()
            const fromId = dragNodeIdRef.current
            if (!fromId || fromId === node.id) {
              return
            }

            setPreviewNodes((current) => {
              const next = moveByIds(current, fromId, node.id)
              previewNodesRef.current = next
              return next
            })
          }}
          onDrop={(event) => {
            event.preventDefault()
            const fromId = readDragID(event.dataTransfer, 'node')
            if (fromId) {
              dragNodeIdRef.current = null
              if (JSON.stringify(previewNodesRef.current.map((item) => item.id)) !== JSON.stringify((nodes ?? []).map((item) => item.id))) {
                void onReorder(previewNodesRef.current)
              }
            }
          }}
        >
          <div className="inventory-row__body">
            <div className="inventory-row__header">
              <strong>{node.name}</strong>
              <div className="inventory-row__header-actions">
                <button
                  type="button"
                  className="icon-button icon-button--small"
                  onClick={() => void onReorder(moveItemByOffset(previewNodes, index, -1))}
                  disabled={actionState[node.id] === 'deleting' || index === 0}
                  aria-label={`Move ${node.name} up`}
                  title="Move up"
                >
                  <ArrowUp aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="icon-button icon-button--small"
                  onClick={() => void onReorder(moveItemByOffset(previewNodes, index, 1))}
                  disabled={actionState[node.id] === 'deleting' || index === previewNodes.length - 1}
                  aria-label={`Move ${node.name} down`}
                  title="Move down"
                >
                  <ArrowDown aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="icon-button icon-button--small"
                  onClick={() => onEdit(node)}
                  disabled={actionState[node.id] === 'deleting'}
                  aria-label={`Edit ${node.name}`}
                  title={`Edit ${node.name}`}
                >
                  <Pencil aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="icon-danger-button"
                  onClick={() => void onDelete(node)}
                  disabled={actionState[node.id] === 'deleting'}
                  aria-label={`Delete ${node.name}`}
                  title={`Delete ${node.name}`}
                >
                  {actionState[node.id] === 'deleting' ? <span className="refresh-spinner" aria-hidden="true" /> : <Trash2 aria-hidden="true" />}
                </button>
                {refreshingItems[node.id] ? <span className="refresh-spinner" aria-label="Refreshing" title="Refreshing" /> : null}
                <span className={`status-pill status-pill--${statusClassName(node.status)}`}>{node.status}</span>
              </div>
            </div>
            <p className="inventory-row__meta">
              <span className="inventory-row__meta-label">TYPE</span>
              <span className="inventory-row__meta-value">{node.nodeType || 'Unknown type'}</span>
            </p>
            <p className="inventory-row__meta">
              <span className="inventory-row__meta-label">IP</span>
              <span className="inventory-row__meta-value">{node.managementIp || 'No management IP'}</span>
            </p>
            <p className="inventory-row__meta">
              <span className="inventory-row__meta-label">VENDOR</span>
              <span className="inventory-row__meta-value">{node.vendor || 'Unknown vendor'}</span>
            </p>
            <p className="inventory-row__meta">
              <span className="inventory-row__meta-label">MODEL</span>
              <span className="inventory-row__meta-value">{node.model || 'Unknown model'}</span>
            </p>
          </div>
          {panelLink ? (
            <div className="inventory-row__actions inventory-row__actions--device">
              <a className="action-button panel-button" href={panelLink} target="_blank" rel="noreferrer">
                <span className="panel-button__icon" aria-hidden="true">
                  {'\u{1F310}'}
                </span>
                <span>Panel</span>
              </a>
            </div>
          ) : null}
          <div className="inventory-row__tags">
            {(node.tags ?? []).map((tag) => (
              <span key={tag} className="tag-pill">
                {tag}
              </span>
            ))}
          </div>
        </article>
        )
      })}
    </div>
  )
}

function SegmentList({
  segments,
  onEdit,
  onDelete,
  actionState,
  onReorder,
}: {
  segments: NetworkSegment[]
  onEdit: (segment: NetworkSegment) => void
  onDelete: (segment: NetworkSegment) => Promise<void>
  actionState: Record<string, string>
  onReorder: (items: NetworkSegment[]) => Promise<void>
}) {
  const [previewSegments, setPreviewSegments] = useState<NetworkSegment[]>(segments ?? [])
  const dragSegmentIdRef = useRef<string | null>(null)
  const previewSegmentsRef = useRef<NetworkSegment[]>(segments ?? [])

  useEffect(() => {
    setPreviewSegments(segments ?? [])
    previewSegmentsRef.current = segments ?? []
  }, [segments])

  if (!segments || segments.length === 0) {
    return <div className="empty-state">Empty</div>
  }

  return (
    <div className="inventory-list inventory-list--cards">
      {(previewSegments ?? []).map((segment, index) => (
        <article
          key={segment.id}
          className="inventory-row inventory-row--draggable"
          draggable
          onDragStart={(event) => {
            dragSegmentIdRef.current = segment.id
            writeDragID(event.dataTransfer, 'segment', segment.id)
          }}
          onDragEnd={() => {
            dragSegmentIdRef.current = null
            setPreviewSegments(segments ?? [])
          }}
          onDragOver={(event) => {
            event.preventDefault()
            const fromId = dragSegmentIdRef.current
            if (!fromId || fromId === segment.id) {
              return
            }

            setPreviewSegments((current) => {
              const next = moveByIds(current, fromId, segment.id)
              previewSegmentsRef.current = next
              return next
            })
          }}
          onDrop={(event) => {
            event.preventDefault()
            const fromId = readDragID(event.dataTransfer, 'segment')
            if (fromId) {
              dragSegmentIdRef.current = null
              if (JSON.stringify(previewSegmentsRef.current.map((item) => item.id)) !== JSON.stringify((segments ?? []).map((item) => item.id))) {
                void onReorder(previewSegmentsRef.current)
              }
            }
          }}
        >
          <div className="inventory-row__body">
            <div className="inventory-row__header">
              <strong>{segment.name}</strong>
              <div className="inventory-row__header-actions">
                <button
                  type="button"
                  className="icon-button icon-button--small"
                  onClick={() => void onReorder(moveItemByOffset(previewSegments, index, -1))}
                  disabled={actionState[segment.id] === 'deleting' || index === 0}
                  aria-label={`Move ${segment.name} up`}
                  title="Move up"
                >
                  <ArrowUp aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="icon-button icon-button--small"
                  onClick={() => void onReorder(moveItemByOffset(previewSegments, index, 1))}
                  disabled={actionState[segment.id] === 'deleting' || index === previewSegments.length - 1}
                  aria-label={`Move ${segment.name} down`}
                  title="Move down"
                >
                  <ArrowDown aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="icon-button icon-button--small"
                  onClick={() => onEdit(segment)}
                  disabled={actionState[segment.id] === 'deleting'}
                  aria-label={`Edit ${segment.name}`}
                  title={`Edit ${segment.name}`}
                >
                  <Pencil aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className="icon-danger-button"
                  onClick={() => void onDelete(segment)}
                  disabled={actionState[segment.id] === 'deleting'}
                  aria-label={`Delete ${segment.name}`}
                  title={`Delete ${segment.name}`}
                >
                  {actionState[segment.id] === 'deleting' ? <span className="refresh-spinner" aria-hidden="true" /> : <Trash2 aria-hidden="true" />}
                </button>
                <span className="status-pill status-pill--mapped">{segment.segmentType}</span>
              </div>
            </div>
            <p className="inventory-row__meta">
              <span className="inventory-row__meta-label">TYPE</span>
              <span className="inventory-row__meta-value">{segment.segmentType || 'Unknown type'}</span>
            </p>
            <p className="inventory-row__meta">
              <span className="inventory-row__meta-label">CIDR</span>
              <span className="inventory-row__meta-value">{segment.cidr || 'No CIDR'}</span>
            </p>
            <p className="inventory-row__meta">
              <span className="inventory-row__meta-label">VLAN</span>
              <span className="inventory-row__meta-value">{segment.vlanId || 'n/a'}</span>
            </p>
            <p className="inventory-row__meta">
              <span className="inventory-row__meta-label">GW</span>
              <span className="inventory-row__meta-value">{segment.gatewayIp || 'n/a'}</span>
            </p>
            <p className="inventory-row__meta">
              <span className="inventory-row__meta-label">DNS</span>
              <span className="inventory-row__meta-value">{segment.dnsDomain || 'n/a'}</span>
            </p>
          </div>
        </article>
      ))}
    </div>
  )
}

function TopologyGraph({
  devices,
  networkNodes,
  networkSegments,
  relations,
}: {
  devices: Device[]
  networkNodes: NetworkNode[]
  networkSegments: NetworkSegment[]
  relations: Relation[]
}) {
  if (
    (!devices || devices.length === 0) &&
    (!networkNodes || networkNodes.length === 0) &&
    (!networkSegments || networkSegments.length === 0) &&
    (!relations || relations.length === 0)
  ) {
    return <div className="empty-state">Empty</div>
  }

  const laneX = {
    segment: 160,
    node: 480,
    device: 800,
  }

  const buildLaneNodes = <T extends { id: string; name: string }>(
    items: T[],
    kind: 'segment' | 'node' | 'device',
    entityKind: Relation['sourceKind'],
    subtitle: (item: T) => string,
  ) =>
    items.map((item, index) => ({
      id: item.id,
      kind,
      entityKind,
      label: item.name,
      subtitle: subtitle(item),
      x: laneX[kind],
      y: 90 + index * 120,
    }))

  const graphNodes = [
    ...buildLaneNodes(networkSegments ?? [], 'segment', 'networkSegment', (segment) => segment.cidr || segment.segmentType || 'segment'),
    ...buildLaneNodes(networkNodes ?? [], 'node', 'networkNode', (node) => node.nodeType || 'node'),
    ...buildLaneNodes(devices ?? [], 'device', 'device', (device) => device.ipAddress || device.hostname || 'device'),
  ]

  const nodeWidth = 208
  const nodeHeight = 68
  const nodeHalfWidth = nodeWidth / 2
  const nodeHalfHeight = nodeHeight / 2

  const anchorForDirection = (
    node: (typeof graphNodes)[number],
    toward: { x: number; y: number },
  ) => {
    const dx = toward.x - node.x
    const dy = toward.y - node.y

    if (Math.abs(dx) >= Math.abs(dy)) {
      return dx >= 0
        ? { x: node.x + nodeHalfWidth, y: node.y, side: 'right' as const }
        : { x: node.x - nodeHalfWidth, y: node.y, side: 'left' as const }
    }

    return dy >= 0
      ? { x: node.x, y: node.y + nodeHalfHeight, side: 'bottom' as const }
      : { x: node.x, y: node.y - nodeHalfHeight, side: 'top' as const }
  }

  const nodeLookup = new Map(graphNodes.map((node) => [topologyEntityKey(node.entityKind, node.id), node]))
  const graphEdges = (relations ?? [])
    .map((relation, relationIndex) => {
      const source = nodeLookup.get(topologyEntityKey(relation.sourceKind, relation.sourceId))
      const target = nodeLookup.get(topologyEntityKey(relation.targetKind, relation.targetId))
      if (!source || !target) {
        return null
      }

      const start = anchorForDirection(source, target)
      const end = anchorForDirection(target, source)
      const controlOffset = 72
      const controlPoint = (anchor: typeof start, direction: 1 | -1) => {
        switch (anchor.side) {
          case 'right':
            return { x: anchor.x + controlOffset * direction, y: anchor.y }
          case 'left':
            return { x: anchor.x - controlOffset * direction, y: anchor.y }
          case 'bottom':
            return { x: anchor.x, y: anchor.y + controlOffset * direction }
          case 'top':
            return { x: anchor.x, y: anchor.y - controlOffset * direction }
        }
      }

      const c1 = controlPoint(start, 1)
      const c2 = controlPoint(end, 1)
      const label = truncateTopologyLabel(relation.relationType, 22)
      const crossesLanes = Math.abs(end.x - start.x) > nodeWidth
      const labelX = crossesLanes ? (start.x + end.x) / 2 : start.x + nodeHalfWidth + 48
      const labelY = (start.y + end.y) / 2 - 10 + (relationIndex % 2) * 16

      return {
        id: relation.id,
        label,
        confidence: relation.confidence,
        x1: start.x,
        y1: start.y,
        x2: end.x,
        y2: end.y,
        c1x: c1.x,
        c1y: c1.y,
        c2x: c2.x,
        c2y: c2.y,
        labelX,
        labelY,
      }
    })
    .filter(Boolean)

  const laneCounts = [networkSegments.length, networkNodes.length, devices.length]
  const maxLaneItems = Math.max(...laneCounts, 1)
  const graphHeight = Math.max(360, 120 + maxLaneItems * 120)

  return (
    <div className="topology-graph">
      <div className="topology-graph__legend">
        <span className="topology-legend-pill topology-legend-pill--segment">Segments</span>
        <span className="topology-legend-pill topology-legend-pill--node">Network nodes</span>
        <span className="topology-legend-pill topology-legend-pill--device">Devices</span>
      </div>
      <div className="topology-graph__canvas" role="region" aria-label="Scrollable network topology" tabIndex={0}>
        <svg viewBox={`0 0 960 ${graphHeight}`} className="topology-graph__svg" role="img" aria-label="Network topology graph">
          <g>
            <text x="160" y="36" textAnchor="middle" className="topology-graph__lane-label">
              Segments
            </text>
            <text x="480" y="36" textAnchor="middle" className="topology-graph__lane-label">
              Network nodes
            </text>
            <text x="800" y="36" textAnchor="middle" className="topology-graph__lane-label">
              Devices
            </text>
          </g>

          {graphEdges.map((edge) => (
            <g key={edge!.id}>
              <title>{`${edge!.label}${edge!.confidence ? ` (${edge!.confidence})` : ''}`}</title>
              <path
                d={`M ${edge!.x1} ${edge!.y1} C ${edge!.c1x} ${edge!.c1y}, ${edge!.c2x} ${edge!.c2y}, ${edge!.x2} ${edge!.y2}`}
                className="topology-graph__edge"
              />
              <text
                x={edge!.labelX}
                y={edge!.labelY}
                textAnchor="middle"
                className="topology-graph__edge-label"
              >
                {edge!.label}
              </text>
            </g>
          ))}

          {graphNodes.map((node) => (
            <g key={`${node.entityKind}:${node.id}`} transform={`translate(${node.x - nodeHalfWidth}, ${node.y - nodeHalfHeight})`}>
              <title>{`${node.label}: ${node.subtitle}`}</title>
              <rect
                width={nodeWidth}
                height={nodeHeight}
                rx="8"
                className={`topology-graph__node topology-graph__node--${node.kind}`}
              />
              <text x="18" y="28" className="topology-graph__node-title">
                {truncateTopologyLabel(node.label)}
              </text>
              <text x="18" y="49" className="topology-graph__node-subtitle">
                {truncateTopologyLabel(node.subtitle, 28)}
              </text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  )
}

function ActionList({ actions }: { actions: Action[] }) {
  if (!actions || actions.length === 0) {
    return <div className="empty-state">Empty</div>
  }

  return (
    <div className="inventory-list">
      {(actions ?? []).map((action) => (
        <article key={action.id} className="inventory-row">
          <div>
            <div className="inventory-row__header">
              <strong>{action.actionType}</strong>
              <span className={`status-pill status-pill--${statusClassName(action.status)}`}>{action.status}</span>
            </div>
            <p className="inventory-row__meta">
              {(action.metadata?.deviceName || action.deviceId)} | {new Date(action.startedAt).toLocaleString()}
            </p>
            <p className="inventory-row__meta">{action.resultSummary}</p>
          </div>
        </article>
      ))}
    </div>
  )
}

function DiscoveryResults({
  result,
  isLoading,
  onCreateDevice,
  onCreateNode,
  onCreateSegment,
}: {
  result: DiscoveryScanResult
  isLoading: boolean
  onCreateDevice: (host: DiscoveryHostMatch) => void
  onCreateNode: (host: DiscoveryHostMatch) => void
  onCreateSegment: (candidate: { cidr: string; name: string }) => void
}) {
  const scannedCidrs = result.scannedCidrs ?? []
  const segmentCandidates = result.segmentCandidates ?? []
  const hosts = result.hosts ?? []

  return (
    <div className="discovery-results">
      <div className="form-note">
        Scanned networks: {scannedCidrs.length > 0 ? scannedCidrs.join(', ') : result.cidr}
      </div>
      {isLoading ? (
        <div className="discovery-streaming-note" role="status" aria-live="polite">
          <span className="refresh-spinner" aria-hidden="true" />
          <span>Scanning network... Found {hosts.length} host{hosts.length === 1 ? '' : 's'} so far.</span>
        </div>
      ) : null}
      {hosts.length === 0 && segmentCandidates.length === 0 ? <div className="empty-state">Empty</div> : null}
      {segmentCandidates.length > 0 ? (
        <div className="discovery-results__section">
          <div className="discovery-results__heading">
            <span className="section-label">Segments</span>
            <span className="status-pill status-pill--mapped">{segmentCandidates.length} candidate{segmentCandidates.length === 1 ? '' : 's'}</span>
          </div>
          <div className="inventory-list discovery-results__grid">
            {segmentCandidates.map((candidate) => (
              <article key={candidate.cidr} className="inventory-row discovery-card discovery-card--segment">
                <div className="inventory-row__body">
                  <div className="inventory-row__header">
                    <strong>{candidate.name}</strong>
                    <span className="status-pill status-pill--mapped">Segment</span>
                  </div>
                  <p className="inventory-row__meta">
                    <span className="inventory-row__meta-label">CIDR</span>
                    <span className="inventory-row__meta-value">{candidate.cidr}</span>
                  </p>
                </div>
                <div className="inventory-row__actions inventory-row__actions--device">
                  <button type="button" className="action-button" onClick={() => onCreateSegment(candidate)}>
                    Create segment
                  </button>
                </div>
              </article>
            ))}
          </div>
        </div>
      ) : null}

      {hosts.length > 0 ? (
        <div className="discovery-results__section">
          <div className="discovery-results__heading">
            <span className="section-label">Hosts</span>
            <span className="status-pill status-pill--online">{hosts.length} found</span>
          </div>
          <div className="inventory-list discovery-results__grid">
            {hosts.map((host) => (
              <article key={`${host.ipAddress}-${host.macAddress ?? ''}`} className="inventory-row discovery-card">
                <div className="inventory-row__body">
                  <div className="inventory-row__header">
                    <strong>{host.hostname || host.ipAddress}</strong>
                    <span className="status-pill status-pill--online">Discovered</span>
                  </div>
                  <p className="inventory-row__meta">
                    <span className="inventory-row__meta-label">IP</span>
                    <span className="inventory-row__meta-value">{host.ipAddress}</span>
                  </p>
                  <p className="inventory-row__meta">
                    <span className="inventory-row__meta-label">MAC</span>
                    <span className="inventory-row__meta-value">{host.macAddress || 'Not resolved'}</span>
                  </p>
                  <p className="inventory-row__meta">
                    <span className="inventory-row__meta-label">VENDOR</span>
                    <span className="inventory-row__meta-value">{host.vendor || 'Unknown vendor'}</span>
                  </p>
                </div>
                <div className="inventory-row__actions inventory-row__actions--device">
                  <button type="button" className="action-button" onClick={() => onCreateDevice(host)}>
                    Create device
                  </button>
                  <button type="button" className="action-button" onClick={() => onCreateNode(host)}>
                    Create node
                  </button>
                </div>
              </article>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default function App() {
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const stateRef = useRef<LoadState>({ kind: 'loading' })
  const [actionState, setActionState] = useState<Record<string, string>>({})
  const [sshConfigured, setSSHConfigured] = useState<Record<string, boolean>>({})
  const [inventoryLayoutMode, setInventoryLayoutMode] = useState<'columns' | 'tabs'>('columns')
  const [visibleInventoryPanel, setVisibleInventoryPanel] = useState<'devices' | 'nodes' | 'segments'>('devices')
  const [deviceDraft, setDeviceDraft] = useState<DeviceDraft>(initialDeviceDraft)
  const [deviceSubmitState, setDeviceSubmitState] = useState<'idle' | 'saving'>('idle')
  const [isCreateDeviceOpen, setIsCreateDeviceOpen] = useState(false)
  const [editingDeviceId, setEditingDeviceId] = useState<string | null>(null)
  const [nodeDraft, setNodeDraft] = useState<NetworkNodeDraft>(initialNetworkNodeDraft)
  const [nodeSubmitState, setNodeSubmitState] = useState<'idle' | 'saving'>('idle')
  const [isNodeModalOpen, setIsNodeModalOpen] = useState(false)
  const [editingNodeId, setEditingNodeId] = useState<string | null>(null)
  const [segmentDraft, setSegmentDraft] = useState<NetworkSegmentDraft>(initialNetworkSegmentDraft)
  const [segmentSubmitState, setSegmentSubmitState] = useState<'idle' | 'saving'>('idle')
  const [isSegmentModalOpen, setIsSegmentModalOpen] = useState(false)
  const [editingSegmentId, setEditingSegmentId] = useState<string | null>(null)
  const [modalError, setModalError] = useState<string | null>(null)
  const [sshDraft, setSSHDraft] = useState<SSHCredentialDraft>(initialSSHCredentialDraft)
  const [sshModalDevice, setSSHModalDevice] = useState<Device | null>(null)
  const [sshModalError, setSSHModalError] = useState<string | null>(null)
  const [sshHasStoredPassword, setSSHHasStoredPassword] = useState(false)
  const [sshCapabilityAvailable, setSSHCapabilityAvailable] = useState(true)
  const [sshUnavailableReason, setSSHUnavailableReason] = useState<string | null>(null)
  const [sshEditMode, setSSHEditMode] = useState(false)
  const [sshSubmitState, setSSHSubmitState] = useState<'idle' | 'loading' | 'saving'>('idle')
  const [sshSessionKey, setSSHSessionKey] = useState(0)
  const [sshConnectionState, setSSHConnectionState] = useState('Idle')
  const [toast, setToast] = useState<ToastState>(null)
  const [authState, setAuthState] = useState<'checking' | 'authenticated' | 'unauthenticated'>('checking')
  const [authEnabled, setAuthEnabled] = useState(true)
  const [authUsername, setAuthUsername] = useState('')
  const [loginDraft, setLoginDraft] = useState({ username: '', password: '' })
  const [loginSubmitState, setLoginSubmitState] = useState<'idle' | 'submitting'>('idle')
  const [loginError, setLoginError] = useState<string | null>(null)
  const [sseStatus, setSseStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [refreshingItems, setRefreshingItems] = useState<Record<string, boolean>>({})
  const [actionsState, setActionsState] = useState<'idle' | 'clearing'>('idle')
  const [isActionHistoryOpen, setIsActionHistoryOpen] = useState(false)
  const [isRelationEditorOpen, setIsRelationEditorOpen] = useState(false)
  const [relationSubmitState, setRelationSubmitState] = useState<'idle' | 'saving'>('idle')
  const [relationError, setRelationError] = useState<string | null>(null)
  const [isDiscoveryOpen, setIsDiscoveryOpen] = useState(false)
  const [discoveryCapabilities, setDiscoveryCapabilities] = useState<DiscoveryCapabilities | null>(null)
  const [discoveryCIDR, setDiscoveryCIDR] = useState('')
  const [discoveryState, setDiscoveryState] = useState<'idle' | 'loading'>('idle')
  const [discoveryError, setDiscoveryError] = useState<string | null>(null)
  const [discoveryResult, setDiscoveryResult] = useState<DiscoveryScanResult | null>(null)
  const discoveryStreamRef = useRef<EventSource | null>(null)
  const discoveryRequestRef = useRef<AbortController | null>(null)
  const discoveryGenerationRef = useRef(0)
  const sshRequestGenerationRef = useRef(0)

  useEffect(() => {
    stateRef.current = state
  }, [state])

  async function authFetch(input: RequestInfo | URL, init?: RequestInit) {
    const response = await fetch(input, init)
    if (response.status === 401) {
      setAuthState('unauthenticated')
      throw new Error('Session expired. Please sign in again.')
    }

    return response
  }

  function invalidateDiscoveryStream(): number {
    discoveryGenerationRef.current += 1
    discoveryRequestRef.current?.abort()
    discoveryRequestRef.current = null
    const source = discoveryStreamRef.current
    discoveryStreamRef.current = null
    source?.close()
    return discoveryGenerationRef.current
  }

  function closeDiscoveryModal() {
    invalidateDiscoveryStream()
    setDiscoveryState('idle')
    setIsDiscoveryOpen(false)
  }

  function expireDiscoverySession(generation: number) {
    if (discoveryGenerationRef.current !== generation) {
      return
    }

    invalidateDiscoveryStream()
    setAuthState('unauthenticated')
    setAuthUsername('')
    setDiscoveryState('idle')
    setDiscoveryError(null)
    setIsDiscoveryOpen(false)
    setToast({ kind: 'error', message: 'Session expired. Please sign in again.' })
  }

  async function hasValidDiscoverySession(signal: AbortSignal): Promise<boolean> {
    const response = await fetch('/api/auth/session', { cache: 'no-store', signal })
    if (response.status === 401) {
      return false
    }
    if (!response.ok) {
      throw new Error(`Session check failed with status ${response.status}`)
    }

    const payload = (await response.json()) as { enabled?: unknown; authenticated?: unknown }
    if (typeof payload.enabled !== 'boolean' || typeof payload.authenticated !== 'boolean') {
      throw new Error('Session check returned an invalid response')
    }
    return !payload.enabled || payload.authenticated
  }

  useEffect(() => {
    if (!toast) {
      return
    }

    const timeout = window.setTimeout(() => setToast(null), 5000)
    return () => window.clearTimeout(timeout)
  }, [toast])

  useEffect(() => {
    return () => {
      discoveryGenerationRef.current += 1
      discoveryRequestRef.current?.abort()
      discoveryRequestRef.current = null
      discoveryStreamRef.current?.close()
      discoveryStreamRef.current = null
    }
  }, [])

  useEffect(() => {
    if (authState !== 'unauthenticated') {
      return
    }
    discoveryGenerationRef.current += 1
    discoveryRequestRef.current?.abort()
    discoveryRequestRef.current = null
    discoveryStreamRef.current?.close()
    discoveryStreamRef.current = null
    setDiscoveryState('idle')
    setIsDiscoveryOpen(false)
    setIsCreateDeviceOpen(false)
    setEditingDeviceId(null)
    setDeviceDraft({ ...initialDeviceDraft })
    setIsNodeModalOpen(false)
    setEditingNodeId(null)
    setNodeDraft({ ...initialNetworkNodeDraft })
    setIsSegmentModalOpen(false)
    setEditingSegmentId(null)
    setSegmentDraft({ ...initialNetworkSegmentDraft })
    setIsActionHistoryOpen(false)
    setIsRelationEditorOpen(false)
    setModalError(null)
    setRelationError(null)
    closeSSHModal()
  }, [authState])

  useEffect(() => {
    if (authState !== 'authenticated') {
      return
    }

    setSseStatus('connecting')
    const source = new EventSource('/api/events')

    source.addEventListener('open', () => setSseStatus('connected'))
    source.addEventListener('error', () => setSseStatus('disconnected'))

    source.addEventListener('scan', (e: MessageEvent<string>) => {
      let event: { kind: string; data: unknown }

      try {
        event = JSON.parse(e.data) as { kind: string; data: unknown }
      } catch (error) {
        console.error('Failed to parse scan event payload', error, e.data)
        return
      }

      switch (event.kind) {
        case 'scan-started': {
          const payload = event.data as { deviceIds: string[]; nodeIds: string[] }
          const ids = [...(payload.deviceIds ?? []), ...(payload.nodeIds ?? [])]
          setIsRefreshing(true)
          setRefreshingItems(Object.fromEntries(ids.map((id) => [id, true])))
          break
        }
        case 'device-updated': {
          const device = event.data as Device
          setState((current) =>
            current.kind === 'ready'
              ? { kind: 'ready', data: updateDeviceInSnapshot(current.data, device) }
              : current,
          )
          setRefreshingItems((current) => {
            const next = { ...current }
            delete next[device.id]
            return next
          })
          break
        }
        case 'node-updated': {
          const node = event.data as NetworkNode
          setState((current) =>
            current.kind === 'ready'
              ? { kind: 'ready', data: updateNetworkNodeInSnapshot(current.data, node) }
              : current,
          )
          setRefreshingItems((current) => {
            const next = { ...current }
            delete next[node.id]
            return next
          })
          break
        }
        case 'scan-complete':
          setIsRefreshing(false)
          setRefreshingItems({})
          break
        case 'stream-reset':
          setIsRefreshing(false)
          setRefreshingItems({})
          void loadInventory()
          break
      }
    })

    return () => source.close()
  }, [authState])

  async function loadInventory() {
    try {
      const response = await authFetch('/api/inventory')
      if (!response.ok) {
        throw new Error(`Inventory request failed with status ${response.status}`)
      }

      const data = (await response.json()) as InventorySnapshot
      setState({ kind: 'ready', data })
    } catch (error) {
      setState({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Unknown inventory error',
      })
    }
  }

  async function openDiscoveryModal() {
    const generation = invalidateDiscoveryStream()
    const request = new AbortController()
    discoveryRequestRef.current = request
    setIsDiscoveryOpen(true)
    setDiscoveryCapabilities(null)
    setDiscoveryCIDR('')
    setDiscoveryError(null)
    setDiscoveryResult(null)
    setDiscoveryState('loading')
    try {
      const response = await authFetch('/api/discovery/capabilities', { signal: request.signal })
      if (discoveryGenerationRef.current !== generation) {
        return
      }
      if (!response.ok) {
        throw new Error(`Discovery capabilities request failed with status ${response.status}`)
      }
      const capabilities = (await response.json()) as DiscoveryCapabilities
      if (discoveryGenerationRef.current !== generation) {
        return
      }
      setDiscoveryCapabilities(capabilities)
    } catch (error) {
      if (discoveryGenerationRef.current !== generation) {
        return
      }
      setDiscoveryError(error instanceof Error ? error.message : 'Failed to load discovery capabilities')
    } finally {
      if (discoveryRequestRef.current === request) {
        discoveryRequestRef.current = null
      }
      if (discoveryGenerationRef.current === generation) {
        setDiscoveryState('idle')
      }
    }
  }

  async function scanNetwork() {
    if (discoveryCIDR.trim() && !isValidCIDR(discoveryCIDR)) {
      setDiscoveryError('CIDR must look like 192.168.1.0/24.')
      return
    }

    const generation = invalidateDiscoveryStream()
    const preflightRequest = new AbortController()
    discoveryRequestRef.current = preflightRequest

    const targetCIDR = discoveryCIDR.trim()
    setDiscoveryState('loading')
    setDiscoveryError(null)
    setDiscoveryResult({
      provider: 'nmap',
      cidr: targetCIDR || 'auto',
      scannedCidrs: [],
      hosts: [],
      segmentCandidates: [],
    })

    try {
      const sessionValid = await hasValidDiscoverySession(preflightRequest.signal)
      if (discoveryGenerationRef.current !== generation) {
        return
      }
      if (!sessionValid) {
        expireDiscoverySession(generation)
        return
      }
      if (discoveryRequestRef.current === preflightRequest) {
        discoveryRequestRef.current = null
      }
    } catch (error) {
      if (discoveryGenerationRef.current !== generation) {
        return
      }
      setDiscoveryError(error instanceof Error ? error.message : 'Failed to verify the current session')
      setDiscoveryState('idle')
      return
    } finally {
      if (discoveryRequestRef.current === preflightRequest) {
        discoveryRequestRef.current = null
      }
    }

    const query = targetCIDR ? `?cidr=${encodeURIComponent(targetCIDR)}` : ''
    const source = new EventSource(`/api/discovery/scan/stream${query}`)
    discoveryStreamRef.current = source

    let finished = false

    const isCurrent = () =>
      discoveryGenerationRef.current === generation && discoveryStreamRef.current === source

    const detach = () => {
      source.close()
      if (discoveryStreamRef.current === source) {
        discoveryStreamRef.current = null
      }
    }

    const fail = (message: string) => {
      if (!isCurrent()) {
        return
      }
      finished = true
      detach()
      setDiscoveryError(message)
      setDiscoveryState('idle')
    }

    source.addEventListener('discovery-host', (event: MessageEvent<string>) => {
      if (!isCurrent()) {
        return
      }

      let host: DiscoveryHostMatch
      try {
        host = parseDiscoveryHostEvent(event.data)
      } catch (error) {
        fail(error instanceof Error ? error.message : 'Discovery stream sent an invalid host update.')
        return
      }

      setDiscoveryResult((current) => {
        if (discoveryGenerationRef.current !== generation || !current) {
          return current
        }
        const hosts = [...current.hosts]
        const index = hosts.findIndex((item) => item.ipAddress === host.ipAddress)
        if (index === -1) {
          hosts.push(host)
        } else {
          hosts[index] = host
        }
        return { ...current, hosts }
      })
    })

    source.addEventListener('discovery-complete', (event: MessageEvent<string>) => {
      if (!isCurrent()) {
        return
      }

      let result: DiscoveryScanResult
      try {
        result = parseDiscoveryCompleteEvent(event.data)
      } catch (error) {
        fail(error instanceof Error ? error.message : 'Discovery stream sent an invalid completion response.')
        return
      }

      finished = true
      detach()
      setDiscoveryResult(result)
      setDiscoveryState('idle')
    })

    source.addEventListener('discovery-error', (event: MessageEvent<string>) => {
      if (!isCurrent()) {
        return
      }

      let message: string
      try {
        message = parseDiscoveryErrorEvent(event.data)
      } catch (error) {
        fail(error instanceof Error ? error.message : 'Discovery stream sent an invalid error response.')
        return
      }

      finished = true
      detach()
      setDiscoveryError(message)
      setDiscoveryState('idle')
    })

    source.onerror = () => {
      if (finished || !isCurrent()) {
        return
      }
      finished = true
      detach()

      void (async () => {
        const sessionRequest = new AbortController()
        discoveryRequestRef.current = sessionRequest
        try {
          const sessionValid = await hasValidDiscoverySession(sessionRequest.signal)
          if (discoveryGenerationRef.current !== generation) {
            return
          }
          if (!sessionValid) {
            expireDiscoverySession(generation)
            return
          }
        } catch {
          if (discoveryGenerationRef.current !== generation) {
            return
          }
        } finally {
          if (discoveryRequestRef.current === sessionRequest) {
            discoveryRequestRef.current = null
          }
        }

        if (discoveryGenerationRef.current === generation) {
          setDiscoveryError('Discovery scan failed')
          setDiscoveryState('idle')
        }
      })()
    }
  }

  async function submitLogin() {
    setLoginError(null)
    if (!loginDraft.username.trim() || !loginDraft.password) {
      setLoginError('Username and password are required.')
      return
    }

    setLoginSubmitState('submitting')
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: loginDraft.username.trim(),
          password: loginDraft.password,
        }),
      })

      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Login failed with status ${response.status}`)
      }

      setAuthState('authenticated')
      setAuthUsername(loginDraft.username.trim())
      setLoginDraft({ username: loginDraft.username.trim(), password: '' })
      setToast({ kind: 'success', message: 'Authenticated successfully.' })
    } catch (error) {
      setLoginError(error instanceof Error ? error.message : 'Login failed')
    } finally {
      setLoginSubmitState('idle')
    }
  }

  async function logout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
    } finally {
      setAuthState('unauthenticated')
      setAuthUsername('')
      setLoginDraft({ username: '', password: '' })
      setToast({ kind: 'success', message: 'Signed out.' })
    }
  }

  useEffect(() => {
    let cancelled = false

    async function checkSession() {
      try {
        const response = await fetch('/api/auth/session')
        const payload = (await response.json()) as {
          enabled: boolean
          authenticated: boolean
          username?: string
        }

        if (!cancelled) {
          setAuthEnabled(payload.enabled)
          setAuthUsername(payload.username ?? '')
          setAuthState(!payload.enabled || payload.authenticated ? 'authenticated' : 'unauthenticated')
        }
      } catch (error) {
        if (!cancelled) {
          setAuthState('unauthenticated')
        }
      }
    }

    void checkSession()

    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (authState !== 'authenticated') {
      return
    }

    void loadInventory()
  }, [authState])

  async function persistInventoryOrder(
    kind: 'device' | 'networkNode' | 'networkSegment',
    items: Array<{ id: string; version: number }>,
  ) {
    const response = await authFetch('/api/inventory/order', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        kind,
        items: items.map(({ id, version }) => ({ id, version })),
      }),
    })
    if (!response.ok) {
      const payload = (await response.json()) as { error?: string }
      throw new Error(payload.error ?? `Failed to persist ${kind} order`)
    }
  }

  async function refreshDevices() {
    if (authState !== 'authenticated') {
      return
    }
    const currentState = stateRef.current
    if (currentState.kind !== 'ready' || isRefreshing) {
      return
    }

    const deviceIDs = currentState.data.devices.map((device) => device.id)
    const nodeIDs = currentState.data.networkNodes.map((node) => node.id)
    setIsRefreshing(true)
    setRefreshingItems(Object.fromEntries([...deviceIDs, ...nodeIDs].map((id) => [id, true])))

    try {
      const response = await authFetch('/api/devices/refresh', { method: 'POST' })
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Refresh failed with status ${response.status}`)
      }
      const result = parseBulkRefreshResponse(await response.json())
      setState({ kind: 'ready', data: result.snapshot })
      setToast({
        kind: result.summary.partial ? 'error' : 'success',
        message: `Refresh ${result.summary.partial ? 'completed partially' : 'completed'}: ${result.summary.online} online, ${result.summary.degraded} degraded, ${result.summary.offline} offline, ${result.summary.unknown} unknown${result.summary.skipped > 0 ? `, ${result.summary.skipped} skipped` : ''}.`,
      })
    } catch (error) {
      setToast({ kind: 'error', message: error instanceof Error ? error.message : 'Live status refresh failed.' })
    } finally {
      setIsRefreshing(false)
      setRefreshingItems({})
    }
  }

  async function reorderDevices(items: Device[]) {
    const current = stateRef.current
    if (current.kind !== 'ready') {
      return
    }

    const nextDevices = items
    setState((existing) =>
      existing.kind === 'ready' ? { kind: 'ready', data: { ...existing.data, devices: nextDevices } } : existing,
    )

    try {
      await persistInventoryOrder('device', nextDevices)
      await loadInventory()
    } catch (error) {
      setToast({ kind: 'error', message: error instanceof Error ? error.message : 'Failed to reorder devices' })
      await loadInventory()
    }
  }

  async function reorderNodes(items: NetworkNode[]) {
    const current = stateRef.current
    if (current.kind !== 'ready') {
      return
    }

    const nextNodes = items
    setState((existing) =>
      existing.kind === 'ready' ? { kind: 'ready', data: { ...existing.data, networkNodes: nextNodes } } : existing,
    )

    try {
      await persistInventoryOrder('networkNode', nextNodes)
      await loadInventory()
    } catch (error) {
      setToast({ kind: 'error', message: error instanceof Error ? error.message : 'Failed to reorder network nodes' })
      await loadInventory()
    }
  }

  async function reorderSegments(items: NetworkSegment[]) {
    const current = stateRef.current
    if (current.kind !== 'ready') {
      return
    }

    const nextSegments = items
    setState((existing) =>
      existing.kind === 'ready' ? { kind: 'ready', data: { ...existing.data, networkSegments: nextSegments } } : existing,
    )

    try {
      await persistInventoryOrder('networkSegment', nextSegments)
      await loadInventory()
    } catch (error) {
      setToast({ kind: 'error', message: error instanceof Error ? error.message : 'Failed to reorder network segments' })
      await loadInventory()
    }
  }

  async function saveRelation(draft: RelationDraft, relationId: string | null): Promise<boolean> {
    setRelationError(null)
    if (
      draft.sourceKind === draft.targetKind &&
      draft.sourceId === draft.targetId
    ) {
      setRelationError('Source and target must be different.')
      return false
    }
    if (!draft.relationType.trim()) {
      setRelationError('Relation type is required.')
      return false
    }

    const existing =
      relationId && stateRef.current.kind === 'ready'
        ? stateRef.current.data.relations.find((relation) => relation.id === relationId)
        : undefined
    const id = relationId ?? createRelationID()
    setRelationSubmitState('saving')
    try {
      const response = await authFetch(relationId ? `/api/relations/${relationId}` : '/api/relations', {
        method: relationId ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id,
          version: existing?.version,
          ...draft,
          relationType: draft.relationType.trim(),
          confidence: draft.confidence || 'manual',
          metadata: existing?.metadata ?? {},
        }),
      })
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Relation save failed with status ${response.status}`)
      }

      await loadInventory()
      setToast({ kind: 'success', message: `Relation ${relationId ? 'updated' : 'created'} successfully.` })
      return true
    } catch (error) {
      setRelationError(error instanceof Error ? error.message : 'Relation save failed')
      return false
    } finally {
      setRelationSubmitState('idle')
    }
  }

  async function deleteRelation(relation: Relation) {
    if (!window.confirm(`Delete the ${relation.relationType} relation?`)) {
      return
    }

    setRelationError(null)
    setRelationSubmitState('saving')
    try {
      const response = await authFetch(`/api/relations/${relation.id}`, {
        method: 'DELETE',
        headers: { 'If-Match': `"${relation.version}"` },
      })
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Relation delete failed with status ${response.status}`)
      }
      await loadInventory()
      setToast({ kind: 'success', message: 'Relation deleted successfully.' })
    } catch (error) {
      setRelationError(error instanceof Error ? error.message : 'Relation delete failed')
    } finally {
      setRelationSubmitState('idle')
    }
  }

  function closeSSHModal() {
    sshRequestGenerationRef.current += 1
    setSSHModalError(null)
    setSSHModalDevice(null)
    setSSHDraft({ ...initialSSHCredentialDraft })
    setSSHHasStoredPassword(false)
    setSSHCapabilityAvailable(true)
    setSSHUnavailableReason(null)
    setSSHEditMode(false)
    setSSHSubmitState('idle')
    setSSHSessionKey(0)
    setSSHConnectionState('Idle')
  }

  async function openSSHModal(device: Device) {
    const generation = sshRequestGenerationRef.current + 1
    sshRequestGenerationRef.current = generation
    setActionState((current) => ({ ...current, [device.id]: 'ssh' }))
    setSSHModalDevice(device)
    setSSHModalError(null)
    setSSHSubmitState('loading')
    setSSHDraft({ ...initialSSHCredentialDraft })
    setSSHHasStoredPassword(false)
    setSSHCapabilityAvailable(true)
    setSSHUnavailableReason(null)
    setSSHEditMode(false)
    setSSHSessionKey(0)
    setSSHConnectionState('Loading credentials...')

    try {
      const response = await authFetch(`/api/devices/${device.id}/ssh-credential`)
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `SSH credential request failed with status ${response.status}`)
      }

      const credential = (await response.json()) as SSHCredential
      if (sshRequestGenerationRef.current !== generation) {
        return
      }
      const { available, reason: unavailableReason } = resolveSSHCapability(credential)
      setSSHDraft({
        username: credential.username ?? '',
        password: '',
        sshPort: credential.sshPort || '22',
      })
      setSSHHasStoredPassword(Boolean(credential.hasPassword))
      setSSHCapabilityAvailable(available)
      setSSHUnavailableReason(unavailableReason)
      setSSHEditMode(available && !credential.hasPassword)
      setSSHConnectionState(
        !available ? 'SSH unavailable' : credential.hasPassword ? 'Connecting...' : 'Credentials required',
      )
      if (available && credential.hasPassword) {
        setSSHSessionKey((current) => current + 1)
      }
      setSSHConfigured((current) => ({ ...current, [device.id]: available && Boolean(credential.hasPassword) }))
    } catch (error) {
      if (sshRequestGenerationRef.current === generation) {
        setSSHModalError(error instanceof Error ? error.message : 'Failed to load SSH credentials')
        setSSHConnectionState('Credential load failed')
      }
    } finally {
      if (sshRequestGenerationRef.current === generation) {
        setSSHSubmitState('idle')
      }
      setActionState((current) => {
        const next = { ...current }
        delete next[device.id]
        return next
      })
    }
  }

  async function triggerWake(device: Device) {
    setActionState((current) => ({ ...current, [device.id]: 'running' }))
    try {
      const response = await authFetch(`/api/devices/${device.id}/wake`, { method: 'POST' })
      if (!response.ok) {
        const payload = (await response.json()) as { resultSummary?: string; error?: string }
        throw new Error(payload.resultSummary ?? payload.error ?? `Wake failed with status ${response.status}`)
      }

      await loadInventory()
      setActionState((current) => ({ ...current, [device.id]: 'completed' }))
      setToast({ kind: 'success', message: `Wake-on-LAN sent to ${device.name}.` })
    } catch (error) {
      setActionState((current) => ({ ...current, [device.id]: 'failed' }))
      setToast({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Wake-on-LAN failed',
      })
    }
  }

  async function createDevice() {
    setModalError(null)

    if (!deviceDraft.name.trim()) {
      setModalError('Device name is required.')
      return
    }
    const panelError = panelURLValidationError(deviceDraft.panelLink)
    if (panelError) {
      setModalError(panelError)
      return
    }
    const panelLink = normalizePanelURL(deviceDraft.panelLink)

    setDeviceSubmitState('saving')
    try {
      const response = await authFetch('/api/devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: deviceDraft.name.trim(),
          hostname: deviceDraft.hostname.trim(),
          role: deviceDraft.role.trim(),
          deviceType: deviceDraft.deviceType.trim(),
          ipAddress: deviceDraft.ipAddress.trim(),
          macAddress: deviceDraft.macAddress.trim(),
          networkSegment: deviceDraft.networkSegment.trim(),
          tags: deviceDraft.tags.map((tag) => tag.trim()).filter(Boolean),
          metadata: panelLink
            ? { panelLink, panelLinkSource: 'manual' }
            : {},
        }),
      })

      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Create failed with status ${response.status}`)
      }

      setDeviceDraft(initialDeviceDraft)
      setIsCreateDeviceOpen(false)
      await loadInventory()
      setToast({ kind: 'success', message: 'Device created successfully.' })
    } catch (error) {
      setModalError(error instanceof Error ? error.message : 'Create device failed')
    } finally {
      setDeviceSubmitState('idle')
    }
  }

  function openCreateDeviceModal() {
    setModalError(null)
    setEditingDeviceId(null)
    setDeviceDraft(initialDeviceDraft)
    setIsCreateDeviceOpen(true)
  }

  function openCreateDeviceFromDiscovery(host: DiscoveryHostMatch) {
    setModalError(null)
    setEditingDeviceId(null)
    setDeviceDraft({
      ...initialDeviceDraft,
      name: host.hostname || host.ipAddress,
      hostname: host.hostname || '',
      ipAddress: host.ipAddress,
      macAddress: host.macAddress || '',
    })
    closeDiscoveryModal()
    setIsCreateDeviceOpen(true)
  }

  function openEditDeviceModal(device: Device) {
    setModalError(null)
    setEditingDeviceId(device.id)
    setDeviceDraft({
      name: device.name ?? '',
      hostname: device.hostname ?? '',
      role: device.role ?? '',
      deviceType: device.deviceType ?? '',
      ipAddress: device.ipAddress ?? '',
      macAddress: device.macAddress ?? '',
      panelLink: getSafePanelLink(device.metadata),
      networkSegment: device.networkSegment ?? '',
      tags: device.tags ?? [],
    })
    setIsCreateDeviceOpen(true)
  }

  async function saveDevice() {
    if (editingDeviceId) {
      setModalError(null)
      if (!deviceDraft.name.trim()) {
        setModalError('Device name is required.')
        return
      }
      const panelError = panelURLValidationError(deviceDraft.panelLink)
      if (panelError) {
        setModalError(panelError)
        return
      }
      const panelLink = normalizePanelURL(deviceDraft.panelLink)

      setDeviceSubmitState('saving')
      try {
        const currentDevice =
          state.kind === 'ready' ? state.data.devices.find((device) => device.id === editingDeviceId) : null

        const response = await authFetch(`/api/devices/${editingDeviceId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: editingDeviceId,
            version: currentDevice?.version,
            name: deviceDraft.name.trim(),
            hostname: deviceDraft.hostname.trim(),
            role: deviceDraft.role.trim(),
            deviceType: deviceDraft.deviceType.trim(),
            ipAddress: deviceDraft.ipAddress.trim(),
            macAddress: deviceDraft.macAddress.trim(),
            networkSegment: deviceDraft.networkSegment.trim(),
            status: currentDevice?.status ?? 'unknown',
            tags: deviceDraft.tags.map((tag) => tag.trim()).filter(Boolean),
            metadata: {
              ...(currentDevice?.metadata ?? {}),
              ...(panelLink
                ? { panelLink, panelLinkSource: 'manual' }
                : { panelLink: '', panelLinkSource: '' }),
            },
          }),
        })

        if (!response.ok) {
          const payload = (await response.json()) as { error?: string }
          throw new Error(payload.error ?? `Update failed with status ${response.status}`)
        }

        setIsCreateDeviceOpen(false)
        setEditingDeviceId(null)
        setDeviceDraft(initialDeviceDraft)
        await loadInventory()
        setToast({ kind: 'success', message: 'Device updated successfully.' })
      } catch (error) {
        setModalError(error instanceof Error ? error.message : 'Update device failed')
      } finally {
        setDeviceSubmitState('idle')
      }
      return
    }

    await createDevice()
  }

  function openCreateNodeModal() {
    setModalError(null)
    setEditingNodeId(null)
    setNodeDraft(initialNetworkNodeDraft)
    setIsNodeModalOpen(true)
  }

  function openCreateNodeFromDiscovery(host: DiscoveryHostMatch) {
    setModalError(null)
    setEditingNodeId(null)
    setNodeDraft({
      ...initialNetworkNodeDraft,
      name: host.hostname || host.ipAddress,
      managementIp: host.ipAddress,
      vendor: host.vendor || '',
    })
    closeDiscoveryModal()
    setIsNodeModalOpen(true)
  }

  function openEditNodeModal(node: NetworkNode) {
    setModalError(null)
    setEditingNodeId(node.id)
    setNodeDraft({
      name: node.name ?? '',
      nodeType: node.nodeType ?? '',
      managementIp: node.managementIp ?? '',
      vendor: node.vendor ?? '',
      model: node.model ?? '',
      panelLink: getSafePanelLink(node.metadata),
    })
    setIsNodeModalOpen(true)
  }

  async function saveNode() {
    setModalError(null)
    if (!nodeDraft.name.trim() || !nodeDraft.nodeType.trim()) {
      setModalError('Node name and type are required.')
      return
    }
    const panelError = panelURLValidationError(nodeDraft.panelLink)
    if (panelError) {
      setModalError(panelError)
      return
    }
    const panelLink = normalizePanelURL(nodeDraft.panelLink)

    setNodeSubmitState('saving')
    try {
      const currentNode =
        editingNodeId && state.kind === 'ready'
          ? state.data.networkNodes.find((node) => node.id === editingNodeId) ?? null
          : null

      const response = await authFetch(editingNodeId ? `/api/network-nodes/${editingNodeId}` : '/api/network-nodes', {
        method: editingNodeId ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: editingNodeId ?? undefined,
          version: currentNode?.version,
          name: nodeDraft.name.trim(),
          nodeType: nodeDraft.nodeType.trim(),
          managementIp: nodeDraft.managementIp.trim(),
          vendor: nodeDraft.vendor.trim(),
          model: nodeDraft.model.trim(),
          status: currentNode?.status ?? 'unknown',
          macAddress: currentNode?.macAddress ?? '',
          tags: currentNode?.tags ?? [],
          metadata: {
            ...(currentNode?.metadata ?? {}),
            ...(panelLink
              ? { panelLink, panelLinkSource: 'manual' }
              : { panelLink: '', panelLinkSource: '' }),
          },
        }),
      })

      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Node save failed with status ${response.status}`)
      }

      setIsNodeModalOpen(false)
      setEditingNodeId(null)
      setNodeDraft(initialNetworkNodeDraft)
      await loadInventory()
      setToast({ kind: 'success', message: `Network node ${editingNodeId ? 'updated' : 'created'} successfully.` })
    } catch (error) {
      setModalError(error instanceof Error ? error.message : 'Save network node failed')
    } finally {
      setNodeSubmitState('idle')
    }
  }

  async function deleteNode(node: NetworkNode) {
    if (!window.confirm(`Delete network node ${node.name}? Its topology relations will also be removed.`)) {
      return
    }
    setActionState((current) => ({ ...current, [node.id]: 'deleting' }))
    try {
      const response = await authFetch(`/api/network-nodes/${node.id}`, {
        method: 'DELETE',
        headers: { 'If-Match': `"${node.version}"` },
      })
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Delete failed with status ${response.status}`)
      }

      await loadInventory()
      setActionState((current) => {
        const next = { ...current }
        delete next[node.id]
        return next
      })
      setToast({ kind: 'success', message: `Network node ${node.name} deleted.` })
    } catch (error) {
      setActionState((current) => ({ ...current, [node.id]: 'failed' }))
      setToast({ kind: 'error', message: error instanceof Error ? error.message : 'Delete network node failed' })
    }
  }

  function openCreateSegmentModal() {
    setModalError(null)
    setEditingSegmentId(null)
    setSegmentDraft(initialNetworkSegmentDraft)
    setIsSegmentModalOpen(true)
  }

  function openCreateSegmentFromDiscovery(candidate: { cidr: string; name: string }) {
    setModalError(null)
    setEditingSegmentId(null)
    setSegmentDraft({
      ...initialNetworkSegmentDraft,
      name: candidate.name,
      segmentType: 'lan',
      cidr: candidate.cidr,
    })
    closeDiscoveryModal()
    setIsSegmentModalOpen(true)
  }

  function openEditSegmentModal(segment: NetworkSegment) {
    setModalError(null)
    setEditingSegmentId(segment.id)
    setSegmentDraft({
      name: segment.name ?? '',
      segmentType: segment.segmentType ?? '',
      cidr: segment.cidr ?? '',
      vlanId: segment.vlanId ? String(segment.vlanId) : '',
      gatewayIp: segment.gatewayIp ?? '',
      dnsDomain: segment.dnsDomain ?? '',
    })
    setIsSegmentModalOpen(true)
  }

  async function saveSegment() {
    setModalError(null)
    if (!segmentDraft.name.trim() || !segmentDraft.segmentType.trim()) {
      setModalError('Segment name and type are required.')
      return
    }

    setSegmentSubmitState('saving')
    try {
      const currentSegment =
        editingSegmentId && state.kind === 'ready'
          ? state.data.networkSegments.find((segment) => segment.id === editingSegmentId) ?? null
          : null

      const response = await authFetch(
        editingSegmentId ? `/api/network-segments/${editingSegmentId}` : '/api/network-segments',
        {
          method: editingSegmentId ? 'PUT' : 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: editingSegmentId ?? undefined,
            version: currentSegment?.version,
            name: segmentDraft.name.trim(),
            segmentType: segmentDraft.segmentType.trim(),
            cidr: segmentDraft.cidr.trim(),
            vlanId: Number.parseInt(segmentDraft.vlanId, 10) || 0,
            gatewayIp: segmentDraft.gatewayIp.trim(),
            dnsDomain: segmentDraft.dnsDomain.trim(),
            metadata: currentSegment?.metadata ?? {},
          }),
        },
      )

      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Segment save failed with status ${response.status}`)
      }

      setIsSegmentModalOpen(false)
      setEditingSegmentId(null)
      setSegmentDraft(initialNetworkSegmentDraft)
      await loadInventory()
      setToast({ kind: 'success', message: `Network segment ${editingSegmentId ? 'updated' : 'created'} successfully.` })
    } catch (error) {
      setModalError(error instanceof Error ? error.message : 'Save network segment failed')
    } finally {
      setSegmentSubmitState('idle')
    }
  }

  async function deleteSegment(segment: NetworkSegment) {
    if (!window.confirm(`Delete network segment ${segment.name}? Its topology relations will also be removed.`)) {
      return
    }
    setActionState((current) => ({ ...current, [segment.id]: 'deleting' }))
    try {
      const response = await authFetch(`/api/network-segments/${segment.id}`, {
        method: 'DELETE',
        headers: { 'If-Match': `"${segment.version}"` },
      })
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Delete failed with status ${response.status}`)
      }

      await loadInventory()
      setActionState((current) => {
        const next = { ...current }
        delete next[segment.id]
        return next
      })
      setToast({ kind: 'success', message: `Network segment ${segment.name} deleted.` })
    } catch (error) {
      setActionState((current) => ({ ...current, [segment.id]: 'failed' }))
      setToast({ kind: 'error', message: error instanceof Error ? error.message : 'Delete network segment failed' })
    }
  }

  async function saveSSHCredential() {
    if (!sshModalDevice) {
      return
    }

    setSSHModalError(null)

    if (!sshCapabilityAvailable) {
      setSSHModalError(sshUnavailableReason ?? 'SSH credential storage is unavailable.')
      return
    }

    if (!sshDraft.username.trim()) {
      setSSHModalError('SSH username is required.')
      return
    }
    if (!sshDraft.password) {
      setSSHModalError('SSH password is required.')
      return
    }

    const device = sshModalDevice
    const generation = sshRequestGenerationRef.current
    setSSHSubmitState('saving')
    try {
      const response = await authFetch(`/api/devices/${device.id}/ssh-credential`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'If-Match': `"${device.version}"` },
        body: JSON.stringify({
          username: sshDraft.username.trim(),
          password: sshDraft.password,
          sshPort: sshDraft.sshPort.trim(),
        }),
      })

      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `SSH save failed with status ${response.status}`)
      }
      const savedCredential = (await response.json()) as SSHCredential

      if (sshRequestGenerationRef.current !== generation) {
        return
      }
      setSSHConfigured((current) => ({ ...current, [device.id]: true }))
      setSSHHasStoredPassword(true)
      setSSHEditMode(false)
      setSSHDraft((current) => ({ ...current, password: '' }))
      setSSHConnectionState('Connecting...')
      setSSHSessionKey((current) => current + 1)
      setSSHModalDevice((current) =>
        current && current.id === device.id
          ? {
              ...current,
              version: current.version + 1,
              metadata: { ...(current.metadata ?? {}), sshPort: savedCredential.sshPort || '22' },
            }
          : current,
      )
      await loadInventory()
      setToast({ kind: 'success', message: `SSH credentials saved for ${device.name}.` })
    } catch (error) {
      if (sshRequestGenerationRef.current === generation) {
        setSSHModalError(error instanceof Error ? error.message : 'Failed to save SSH credentials')
      }
    } finally {
      if (sshRequestGenerationRef.current === generation) {
        setSSHSubmitState('idle')
      }
    }
  }

  async function deleteSSHCredential() {
    if (!sshModalDevice || !window.confirm(`Remove the stored SSH credentials for ${sshModalDevice.name}?`)) {
      return
    }

    const device = sshModalDevice
    const generation = sshRequestGenerationRef.current
    setSSHModalError(null)
    setSSHSubmitState('saving')
    try {
      const response = await authFetch(`/api/devices/${device.id}/ssh-credential`, {
        method: 'DELETE',
        headers: { 'If-Match': `"${device.version}"` },
      })
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `SSH credential delete failed with status ${response.status}`)
      }
      if (sshRequestGenerationRef.current !== generation) {
        return
      }

      setSSHConfigured((current) => ({ ...current, [device.id]: false }))
      setSSHHasStoredPassword(false)
      setSSHEditMode(true)
      setSSHDraft({ ...initialSSHCredentialDraft })
      setSSHConnectionState('Credentials required')
      setSSHSessionKey((current) => current + 1)
      setSSHModalDevice((current) => {
        if (!current || current.id !== device.id) {
          return current
        }
        const metadata = { ...(current.metadata ?? {}) }
        delete metadata.sshPort
        return { ...current, version: current.version + 1, metadata }
      })
      await loadInventory()
      if (sshRequestGenerationRef.current === generation) {
        setToast({ kind: 'success', message: `SSH credentials removed for ${device.name}.` })
      }
    } catch (error) {
      if (sshRequestGenerationRef.current === generation) {
        setSSHModalError(error instanceof Error ? error.message : 'Failed to remove SSH credentials')
      }
    } finally {
      if (sshRequestGenerationRef.current === generation) {
        setSSHSubmitState('idle')
      }
    }
  }

  async function deleteDevice(device: Device) {
    if (!window.confirm(`Delete device ${device.name}? Its credentials and topology relations will also be removed.`)) {
      return
    }
    setActionState((current) => ({ ...current, [device.id]: 'deleting' }))
    try {
      const response = await authFetch(`/api/devices/${device.id}`, {
        method: 'DELETE',
        headers: { 'If-Match': `"${device.version}"` },
      })
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Delete failed with status ${response.status}`)
      }

      await loadInventory()
      setActionState((current) => {
        const next = { ...current }
        delete next[device.id]
        return next
      })
      setToast({ kind: 'success', message: `Device ${device.name} deleted.` })
    } catch (error) {
      setActionState((current) => ({ ...current, [device.id]: 'failed' }))
      setToast({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Delete device failed',
      })
    }
  }

  async function clearActionHistory() {
    if (!window.confirm('Clear the entire action history?')) {
      return
    }
    setActionsState('clearing')
    try {
      const response = await authFetch('/api/actions', { method: 'DELETE' })
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string }
        throw new Error(payload.error ?? `Clear action history failed with status ${response.status}`)
      }

      await loadInventory()
      setToast({ kind: 'success', message: 'Action history cleared.' })
    } catch (error) {
      setToast({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Failed to clear action history',
      })
    } finally {
      setActionsState('idle')
    }
  }

  const discoveryCIDROptions =
    (discoveryCapabilities?.suggestedCidrs.length ?? 0) > 0
      ? discoveryCapabilities?.suggestedCidrs ?? []
      : discoveryCapabilities?.localCidrs ?? []

  function handleInventoryTabKey(event: ReactKeyboardEvent<HTMLButtonElement>) {
    const panels = ['devices', 'nodes', 'segments'] as const
    const currentIndex = panels.indexOf(visibleInventoryPanel)
    let nextIndex = currentIndex
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        nextIndex = (currentIndex + 1) % panels.length
        break
      case 'ArrowLeft':
      case 'ArrowUp':
        nextIndex = (currentIndex - 1 + panels.length) % panels.length
        break
      case 'Home':
        nextIndex = 0
        break
      case 'End':
        nextIndex = panels.length - 1
        break
      default:
        return
    }
    event.preventDefault()
    const nextPanel = panels[nextIndex]
    setVisibleInventoryPanel(nextPanel)
    window.requestAnimationFrame(() => document.getElementById(`inventory-tab-${nextPanel}`)?.focus())
  }

  const content =
    authState === 'checking' ? (
      <section className="feedback-panel">
        <p className="section-label">Authentication</p>
        <h2>Checking session.</h2>
        <p>The dashboard is waiting for authentication state from the backend.</p>
      </section>
    ) : authState === 'unauthenticated' ? (
      <AuthPanel
        submitState={loginSubmitState}
        errorMessage={loginError}
        draft={loginDraft}
        onChange={(field, value) => setLoginDraft((current) => ({ ...current, [field]: value }))}
        onSubmit={submitLogin}
      />
    ) : state.kind === 'ready' ? (
      <>
        <div className="hero-grid">
          <MetricCard
            title="Endpoint devices"
            value={String(state.data.devices.length)}
            accent="green"
          />
          <MetricCard
            title="Infrastructure nodes"
            value={String(state.data.networkNodes.length)}
            accent="blue"
          />
          <MetricCard
            title="Segments and VLANs"
            value={String(state.data.networkSegments.length)}
            accent="amber"
          />
        </div>

        <section className="toolbar-panel">
          <div className="toolbar-panel__row">
            <div className="toolbar-panel__group">
              <button type="button" className="action-button" onClick={() => void refreshDevices()} disabled={isRefreshing}>
                <RefreshCw aria-hidden="true" />
                {isRefreshing ? 'Refreshing...' : 'Refresh now'}
              </button>
              <button type="button" className="action-button" onClick={() => void openDiscoveryModal()}>
                <ScanLine aria-hidden="true" />
                Scan Network
              </button>
              <span
                className={`secondary-button secondary-button--status secondary-button--status-${sseStatus}${sseStatus === 'connected' ? ' secondary-button--active' : ''}`}
                role="status"
                aria-live="polite"
              >
                {sseStatus === 'connected' ? 'Live: on' : sseStatus === 'connecting' ? 'Connecting...' : 'Live: off'}
              </span>
            </div>
            <div className="toolbar-panel__group toolbar-panel__group--right">
              <button type="button" className="action-button" onClick={() => setIsActionHistoryOpen(true)}>
                <History aria-hidden="true" />
                Action history
              </button>
            </div>
          </div>
        </section>

        <div className="inventory-layout-toolbar">
          <div className="layout-switch" role="group" aria-label="Inventory layout">
            <button
              type="button"
              className={inventoryLayoutMode === 'columns' ? 'layout-switch__button layout-switch__button--active' : 'layout-switch__button'}
              onClick={() => setInventoryLayoutMode('columns')}
              aria-label="Show inventory sections as columns"
              aria-pressed={inventoryLayoutMode === 'columns'}
              title="Columns"
            >
              <Columns3 className="layout-switch__icon" aria-hidden="true" />
              <span>Columns</span>
            </button>
            <button
              type="button"
              className={inventoryLayoutMode === 'tabs' ? 'layout-switch__button layout-switch__button--active' : 'layout-switch__button'}
              onClick={() => setInventoryLayoutMode('tabs')}
              aria-label="Show one inventory section at a time"
              aria-pressed={inventoryLayoutMode === 'tabs'}
              title="Tabs"
            >
              <List className="layout-switch__icon" aria-hidden="true" />
              <span>Tabs</span>
            </button>
          </div>
          {inventoryLayoutMode === 'tabs' ? (
            <div className="inventory-layout-toolbar__tabs" role="tablist" aria-label="Inventory sections">
              <button
                id="inventory-tab-devices"
                type="button"
                className={visibleInventoryPanel === 'devices' ? 'layout-tab layout-tab--active' : 'layout-tab'}
                onClick={() => setVisibleInventoryPanel('devices')}
                role="tab"
                aria-selected={visibleInventoryPanel === 'devices'}
                aria-controls="inventory-panel-devices"
                tabIndex={visibleInventoryPanel === 'devices' ? 0 : -1}
                onKeyDown={handleInventoryTabKey}
              >
                Devices
              </button>
              <button
                id="inventory-tab-nodes"
                type="button"
                className={visibleInventoryPanel === 'nodes' ? 'layout-tab layout-tab--active' : 'layout-tab'}
                onClick={() => setVisibleInventoryPanel('nodes')}
                role="tab"
                aria-selected={visibleInventoryPanel === 'nodes'}
                aria-controls="inventory-panel-nodes"
                tabIndex={visibleInventoryPanel === 'nodes' ? 0 : -1}
                onKeyDown={handleInventoryTabKey}
              >
                Network nodes
              </button>
              <button
                id="inventory-tab-segments"
                type="button"
                className={visibleInventoryPanel === 'segments' ? 'layout-tab layout-tab--active' : 'layout-tab'}
                onClick={() => setVisibleInventoryPanel('segments')}
                role="tab"
                aria-selected={visibleInventoryPanel === 'segments'}
                aria-controls="inventory-panel-segments"
                tabIndex={visibleInventoryPanel === 'segments' ? 0 : -1}
                onKeyDown={handleInventoryTabKey}
              >
                Network segments
              </button>
            </div>
          ) : null}
        </div>

        <section className={inventoryLayoutMode === 'columns' ? 'overview-grid' : 'inventory-stack'}>
          {(inventoryLayoutMode === 'columns' || visibleInventoryPanel === 'devices') ? (
          <article
            className="data-panel"
            id="inventory-panel-devices"
            role={inventoryLayoutMode === 'tabs' ? 'tabpanel' : undefined}
            aria-labelledby={inventoryLayoutMode === 'tabs' ? 'inventory-tab-devices' : undefined}
          >
            <div className="data-panel__heading">
              <p className="section-label">Endpoints</p>
              <div className="panel-title-row">
                <h2>Devices</h2>
                <button
                  type="button"
                  className="icon-button"
                  onClick={openCreateDeviceModal}
                  aria-label="Add device"
                >
                  <Plus aria-hidden="true" />
                </button>
              </div>
            </div>
            <EndpointList
              devices={state.data.devices}
              actionState={actionState}
              sshConfigured={sshConfigured}
              refreshingItems={refreshingItems}
              onEdit={openEditDeviceModal}
              onOpenSSH={openSSHModal}
              onWake={triggerWake}
              onDelete={deleteDevice}
              onReorder={reorderDevices}
            />
          </article>
          ) : null}

          {(inventoryLayoutMode === 'columns' || visibleInventoryPanel === 'nodes') ? (
          <article
            className="data-panel"
            id="inventory-panel-nodes"
            role={inventoryLayoutMode === 'tabs' ? 'tabpanel' : undefined}
            aria-labelledby={inventoryLayoutMode === 'tabs' ? 'inventory-tab-nodes' : undefined}
          >
            <div className="data-panel__heading">
              <p className="section-label">Infrastructure</p>
              <div className="panel-title-row">
                <h2>Network nodes</h2>
                <button type="button" className="icon-button" onClick={openCreateNodeModal} aria-label="Add network node">
                  <Plus aria-hidden="true" />
                </button>
              </div>
            </div>
            <InfrastructureList
              nodes={state.data.networkNodes}
              onEdit={openEditNodeModal}
              onDelete={deleteNode}
              actionState={actionState}
              refreshingItems={refreshingItems}
              onReorder={reorderNodes}
            />
          </article>
          ) : null}

          {(inventoryLayoutMode === 'columns' || visibleInventoryPanel === 'segments') ? (
          <article
            className="data-panel"
            id="inventory-panel-segments"
            role={inventoryLayoutMode === 'tabs' ? 'tabpanel' : undefined}
            aria-labelledby={inventoryLayoutMode === 'tabs' ? 'inventory-tab-segments' : undefined}
          >
            <div className="data-panel__heading">
              <p className="section-label">Segmentation</p>
              <div className="panel-title-row">
                <h2>Network segments</h2>
                <button type="button" className="icon-button" onClick={openCreateSegmentModal} aria-label="Add network segment">
                  <Plus aria-hidden="true" />
                </button>
              </div>
            </div>
            <SegmentList
              segments={state.data.networkSegments}
              onEdit={openEditSegmentModal}
              onDelete={deleteSegment}
              actionState={actionState}
              onReorder={reorderSegments}
            />
          </article>
          ) : null}

        </section>
        <article className="data-panel data-panel--full">
          <div className="data-panel__heading">
            <p className="section-label">Topology</p>
            <div className="panel-title-row">
              <h2>Topology graph</h2>
              <button
                type="button"
                className="secondary-button"
                onClick={() => {
                  setRelationError(null)
                  setIsRelationEditorOpen(true)
                }}
              >
                <Network aria-hidden="true" />
                Manage relations
              </button>
            </div>
          </div>
          <TopologyGraph
            devices={state.data.devices}
            networkNodes={state.data.networkNodes}
            networkSegments={state.data.networkSegments}
            relations={state.data.relations}
          />
        </article>
      </>
    ) : state.kind === 'error' ? (
      <section className="feedback-panel feedback-panel--error">
        <p className="section-label">Inventory error</p>
        <h2>Backend data could not be loaded.</h2>
        <p>{state.message}</p>
        <button
          type="button"
          className="action-button"
          onClick={() => {
            setState({ kind: 'loading' })
            void loadInventory()
          }}
        >
          Retry inventory
        </button>
      </section>
    ) : (
      <section className="feedback-panel">
        <p className="section-label">Loading</p>
        <h2>Fetching live inventory.</h2>
        <p>The dashboard is waiting for the backend inventory snapshot.</p>
      </section>
    )

  const sshSessionConnected = sshConnectionState === 'Connected'

  return (
    <main className="app-shell">
      <section className="hero-panel">
        <div className="hero-copy">
          <div className="hero-brand">
            <div className="hero-logo" aria-hidden="true">
              <span className="hero-logo__core" />
              <span className="hero-logo__node hero-logo__node--top" />
              <span className="hero-logo__node hero-logo__node--left" />
              <span className="hero-logo__node hero-logo__node--right" />
            </div>
            <div className="hero-brand__text">
              <h1>Home Mesh</h1>
              <p>Network operations</p>
            </div>
          </div>
          <div className="hero-title-row">
            {authState === 'authenticated' && authEnabled ? (
              <div className="hero-user-actions">
                {authUsername ? (
                  <span className="hero-user-badge">
                    <UserCircle className="hero-user-badge__icon" aria-hidden="true" />
                    <span>{authUsername}</span>
                  </span>
                ) : null}
                <button type="button" className="secondary-button" onClick={() => void logout()}>
                  <LogOut aria-hidden="true" />
                  Logout
                </button>
              </div>
            ) : null}
          </div>
        </div>

        {content}
      </section>

      {isCreateDeviceOpen ? (
        <DraggableModal
          label={editingDeviceId ? 'Edit device' : 'New device'}
          title={editingDeviceId ? 'Edit device' : 'Create device'}
          onClose={() => {
            setModalError(null)
            setIsCreateDeviceOpen(false)
            setEditingDeviceId(null)
          }}
        >
          <DeviceForm
            draft={deviceDraft}
            submitState={deviceSubmitState}
            errorMessage={modalError}
            submitLabel={editingDeviceId ? 'Save device' : 'Create device'}
            onChange={(field, value) => setDeviceDraft((current) => ({ ...current, [field]: value }))}
            onToggleTag={(tag) =>
              setDeviceDraft((current) => ({
                ...current,
                tags: current.tags.includes(tag)
                  ? current.tags.filter((value) => value !== tag)
                  : [...current.tags, tag],
              }))
            }
            onSubmit={saveDevice}
          />
        </DraggableModal>
      ) : null}

      {isNodeModalOpen ? (
        <DraggableModal
          label={editingNodeId ? 'Edit node' : 'New node'}
          title={editingNodeId ? 'Edit network node' : 'Create network node'}
          onClose={() => {
            setModalError(null)
            setIsNodeModalOpen(false)
            setEditingNodeId(null)
          }}
        >
          <NetworkNodeForm
            draft={nodeDraft}
            submitState={nodeSubmitState}
            errorMessage={modalError}
            submitLabel={editingNodeId ? 'Save node' : 'Create node'}
            onChange={(field, value) => setNodeDraft((current) => ({ ...current, [field]: value }))}
            onSubmit={saveNode}
          />
        </DraggableModal>
      ) : null}

      {isSegmentModalOpen ? (
        <DraggableModal
          label={editingSegmentId ? 'Edit segment' : 'New segment'}
          title={editingSegmentId ? 'Edit network segment' : 'Create network segment'}
          onClose={() => {
            setModalError(null)
            setIsSegmentModalOpen(false)
            setEditingSegmentId(null)
          }}
        >
          <NetworkSegmentForm
            draft={segmentDraft}
            submitState={segmentSubmitState}
            errorMessage={modalError}
            submitLabel={editingSegmentId ? 'Save segment' : 'Create segment'}
            onChange={(field, value) => setSegmentDraft((current) => ({ ...current, [field]: value }))}
            onSubmit={saveSegment}
          />
        </DraggableModal>
      ) : null}

      {sshModalDevice ? (
        <DraggableModal
          label="SSH access"
          title={sshModalDevice.name}
          widthClassName="modal-panel--wide modal-panel--console"
          onClose={closeSSHModal}
        >
          <CollapsibleSection label="Device" title="Connection details">
            <div className="modal-device-meta">
              <p className="modal-device-meta__row">
                <span className="modal-device-meta__label">DNS</span>
                <span>{sshModalDevice.hostname || 'No hostname'}</span>
              </p>
              <p className="modal-device-meta__row">
                <span className="modal-device-meta__label">IP</span>
                <span>{sshModalDevice.ipAddress || 'No IP address'}</span>
              </p>
              <p className="modal-device-meta__row">
                <span className="modal-device-meta__label">MAC</span>
                <span>{sshModalDevice.macAddress || 'Mac not resolved yet'}</span>
              </p>
              <p className="modal-device-meta__row">
                <span className="modal-device-meta__label">PORT</span>
                <span>{sshDraft.sshPort || sshModalDevice.metadata?.sshPort || '22'}</span>
              </p>
              <p className="form-note">Session state: {sshConnectionState}</p>
              {sshModalError && !sshEditMode ? <div className="inline-error" role="alert">{sshModalError}</div> : null}
            </div>
            {!sshSessionConnected ? (
              <>
              {sshHasStoredPassword && sshCapabilityAvailable ? (
                <div className="ssh-credential-banner">
                  <div>
                    <p className="section-label">Stored credentials</p>
                    <p className="ssh-credential-banner__text">
                      Username: <strong>{sshDraft.username || 'configured'}</strong>
                    </p>
                  </div>
                  <div className="ssh-credential-banner__actions">
                    <button
                      type="button"
                      className="secondary-button"
                      disabled={sshSubmitState !== 'idle'}
                      onClick={() => {
                        setSSHModalError(null)
                        setSSHDraft((current) => ({ ...current, password: '' }))
                        setSSHEditMode((current) => !current)
                      }}
                    >
                      {sshEditMode ? 'Hide credentials' : 'Update credentials'}
                    </button>
                    <button
                      type="button"
                      className="icon-danger-button"
                      disabled={sshSubmitState !== 'idle'}
                      onClick={() => void deleteSSHCredential()}
                      aria-label={`Remove SSH credentials for ${sshModalDevice.name}`}
                      title="Remove SSH credentials"
                    >
                      <Trash2 aria-hidden="true" />
                    </button>
                  </div>
                </div>
              ) : null}
              {sshCapabilityAvailable && sshEditMode ? (
                <SSHCredentialForm
                  draft={sshDraft}
                  submitState={sshSubmitState}
                  errorMessage={sshModalError}
                  hasStoredPassword={sshHasStoredPassword}
                  onChange={(field, value) => setSSHDraft((current) => ({ ...current, [field]: value }))}
                  onSubmit={saveSSHCredential}
                  onCancel={() => {
                    if (sshHasStoredPassword) {
                      setSSHModalError(null)
                      setSSHDraft((current) => ({ ...current, password: '' }))
                      setSSHEditMode(false)
                      setSSHSubmitState('idle')
                      return
                    }
                    closeSSHModal()
                  }}
                />
              ) : null}
              </>
            ) : null}
          </CollapsibleSection>
          {sshSubmitState === 'loading' ? (
            <div className="discovery-loading-state" role="status" aria-live="polite">
              <span className="refresh-spinner" aria-hidden="true" />
              <span>Checking SSH capability...</span>
            </div>
          ) : (
            <SSHTerminalPane
              deviceId={sshModalDevice.id}
              enabled={sshCapabilityAvailable && sshHasStoredPassword && !sshEditMode}
              unavailableReason={sshUnavailableReason}
              sessionKey={sshSessionKey}
              onConnectionState={setSSHConnectionState}
              onReconnect={() => setSSHSessionKey((current) => current + 1)}
            />
          )}
        </DraggableModal>
      ) : null}

      {isActionHistoryOpen && state.kind === 'ready' ? (
        <DraggableModal
          label="Operations"
          title="Action history"
          widthClassName="modal-panel--wide"
          onClose={() => setIsActionHistoryOpen(false)}
        >
          <div className="panel-title-row action-history__header">
            <div className="form-note">Wake-on-LAN and SSH activity recorded by the backend.</div>
            <button
              type="button"
              className="icon-danger-button"
              onClick={() => void clearActionHistory()}
              disabled={actionsState === 'clearing'}
              aria-label="Clear action history"
              title="Clear action history"
            >
              {actionsState === 'clearing' ? <span className="refresh-spinner" aria-hidden="true" /> : <Trash2 aria-hidden="true" />}
            </button>
          </div>
          <ActionList actions={state.data.actions} />
        </DraggableModal>
      ) : null}

      {isRelationEditorOpen && state.kind === 'ready' ? (
        <DraggableModal
          label="Topology"
          title="Manage relations"
          widthClassName="modal-panel--wide"
          onClose={() => {
            setRelationError(null)
            setRelationSubmitState('idle')
            setIsRelationEditorOpen(false)
          }}
        >
          <RelationEditor
            devices={state.data.devices}
            networkNodes={state.data.networkNodes}
            networkSegments={state.data.networkSegments}
            relations={state.data.relations}
            busy={relationSubmitState === 'saving'}
            errorMessage={relationError}
            onSave={saveRelation}
            onDelete={deleteRelation}
          />
        </DraggableModal>
      ) : null}

      {isDiscoveryOpen ? (
        <DraggableModal label="Discovery" title="Scan network" widthClassName="modal-panel--wide modal-panel--discovery" onClose={closeDiscoveryModal}>
          <div className="discovery-modal">
            <div className="discovery-modal__controls">
              <div className="device-form">
                {discoveryError ? <div className="inline-error" role="alert">{discoveryError}</div> : null}
                <div className="form-grid">
                  <label className="form-field">
                    <span>Provider</span>
                    <input
                      value={
                        !discoveryCapabilities && discoveryState === 'loading'
                          ? 'Loading...'
                          : discoveryCapabilities?.nmapAvailable
                            ? 'nmap'
                            : 'Unavailable'
                      }
                      readOnly
                    />
                  </label>
                  <label className="form-field">
                    <span>Custom CIDR override</span>
                    <input
                      list="discovery-cidrs"
                      value={discoveryCIDR}
                      onChange={(event) => setDiscoveryCIDR(event.target.value)}
                      placeholder="Leave empty to scan local networks automatically"
                    />
                    <datalist id="discovery-cidrs">
                      {discoveryCIDROptions.map((cidr) => (
                        <option key={cidr} value={cidr} />
                      ))}
                    </datalist>
                  </label>
                </div>
                <div className="form-note">
                  By default, Home Mesh scans the local networks detected on the host. Provide a custom CIDR only if you want to override that target. Results exclude devices, network nodes, and network segments already present in the inventory.
                </div>
                <div className="form-actions">
                  <button
                    type="button"
                    className="action-button"
                    onClick={() => void scanNetwork()}
                    disabled={discoveryState === 'loading' || !discoveryCapabilities?.nmapAvailable}
                  >
                    {discoveryState === 'loading'
                      ? discoveryCapabilities
                        ? 'Scanning...'
                        : 'Loading...'
                      : 'Run scan'}
                  </button>
                </div>
              </div>
            </div>
            <div className="discovery-modal__results">
              {discoveryResult && (discoveryState !== 'loading' || discoveryResult.hosts.length > 0 || discoveryResult.segmentCandidates.length > 0) ? (
                <DiscoveryResults
                  result={discoveryResult}
                  isLoading={discoveryState === 'loading'}
                  onCreateDevice={openCreateDeviceFromDiscovery}
                  onCreateNode={openCreateNodeFromDiscovery}
                  onCreateSegment={openCreateSegmentFromDiscovery}
                />
              ) : discoveryState === 'loading' ? (
                <div className="discovery-loading-state" role="status" aria-live="polite">
                  <span className="refresh-spinner" aria-hidden="true" />
                  <span>Scanning network...</span>
                </div>
              ) : (
                <div className="empty-state">Empty</div>
              )}
            </div>
          </div>
        </DraggableModal>
      ) : null}

      {toast ? (
        <div
          className={`toast ${toast.kind === 'error' ? 'toast--error' : 'toast--success'}`}
          role={toast.kind === 'error' ? 'alert' : 'status'}
          aria-live={toast.kind === 'error' ? 'assertive' : 'polite'}
        >
          {toast.message}
        </div>
      ) : null}
    </main>
  )
}
