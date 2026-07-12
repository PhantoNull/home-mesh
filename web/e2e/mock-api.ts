import type { Page, Route } from '@playwright/test'
import type { InventorySnapshot } from '../src/models'

type DeterministicMockOptions = {
  sshCredentialDeviceVersion?: number
  sshCredentialExpectedPutVersion?: number
  sshCredentialConflictOnceVersion?: number
  sshCredentialPutDelayMs?: number
  onSSHCredentialPut?: (ifMatch: string | null) => void
  onInventoryGet?: () => void
}

export const inventoryFixture: InventorySnapshot = {
  devices: [
    {
      id: 'device-nas',
      version: 3,
      name: 'NAS Alpha',
      hostname: 'nas-alpha.storage-appliance.home',
      role: 'storage',
      deviceType: 'nas',
      ipAddress: '192.168.10.20',
      macAddress: '02:00:00:00:10:20',
      networkSegment: 'segment-lan',
      status: 'online',
      tags: ['nas', 'server'],
      metadata: { panelLink: 'https://nas-alpha.home' },
    },
  ],
  networkNodes: [
    {
      id: 'node-router',
      version: 2,
      name: 'Core Router',
      nodeType: 'router',
      managementIp: '192.168.10.1',
      macAddress: '02:00:00:00:10:01',
      vendor: 'Home Mesh Labs',
      model: 'HM-R1',
      status: 'online',
      tags: ['router'],
    },
  ],
  networkSegments: [
    {
      id: 'segment-lan',
      version: 4,
      name: 'Primary LAN',
      segmentType: 'lan',
      cidr: '192.168.10.0/24',
      vlanId: 10,
      gatewayIp: '192.168.10.1',
      dnsDomain: 'home.arpa',
    },
  ],
  relations: [
    {
      id: 'relation-segment-router',
      version: 1,
      sourceKind: 'networkSegment',
      sourceId: 'segment-lan',
      targetKind: 'networkNode',
      targetId: 'node-router',
      relationType: 'routed_by',
      confidence: 'manual',
    },
    {
      id: 'relation-router-nas',
      version: 1,
      sourceKind: 'networkNode',
      sourceId: 'node-router',
      targetKind: 'device',
      targetId: 'device-nas',
      relationType: 'connected_to',
      confidence: 'manual',
    },
  ],
  actions: [
    {
      id: 'action-wol',
      deviceId: 'device-nas',
      actionType: 'wake-on-lan',
      status: 'completed',
      resultSummary: 'Magic packet sent',
      startedAt: '2026-01-15T10:30:00Z',
    },
  ],
}

async function fulfillJSON(route: Route, body: unknown, status = 200, headers?: Record<string, string>) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    headers,
    body: JSON.stringify(body),
  })
}

export async function installDeterministicMocks(
  page: Page,
  options: DeterministicMockOptions = {},
): Promise<string[]> {
  let inventorySnapshot = structuredClone(inventoryFixture)
  let currentSSHCredentialVersion = options.sshCredentialDeviceVersion ?? inventoryFixture.devices[0].version
  let expectedSSHCredentialVersion = options.sshCredentialExpectedPutVersion
    ?? currentSSHCredentialVersion
  let shouldConflictSSHCredential = options.sshCredentialConflictOnceVersion !== undefined

  const updateSSHDeviceVersion = (version: number) => {
    inventorySnapshot = {
      ...inventorySnapshot,
      devices: inventorySnapshot.devices.map((device) =>
        device.id === 'device-nas' ? { ...device, version } : device,
      ),
    }
  }

  await page.addInitScript(() => {
    class DeterministicEventSource extends EventTarget {
      static readonly CONNECTING = 0
      static readonly OPEN = 1
      static readonly CLOSED = 2

      readonly CONNECTING = 0
      readonly OPEN = 1
      readonly CLOSED = 2
      readonly url: string
      readonly withCredentials = false
      readyState = DeterministicEventSource.CONNECTING
      onopen: ((event: Event) => void) | null = null
      onmessage: ((event: MessageEvent) => void) | null = null
      onerror: ((event: Event) => void) | null = null

      constructor(url: string | URL) {
        super()
        this.url = String(url)
        const testWindow = window as Window & { __homeMeshEventSources?: DeterministicEventSource[] }
        testWindow.__homeMeshEventSources ??= []
        testWindow.__homeMeshEventSources.push(this)
        window.setTimeout(() => {
          if (this.readyState === DeterministicEventSource.CLOSED) {
            return
          }
          this.readyState = DeterministicEventSource.OPEN
          const event = new Event('open')
          this.dispatchEvent(event)
          this.onopen?.(event)
        }, 0)
      }

      close() {
        this.readyState = DeterministicEventSource.CLOSED
      }
    }

    Object.defineProperty(window, 'EventSource', {
      configurable: true,
      value: DeterministicEventSource,
    })
  })

  const unexpectedRequests: string[] = []
  await page.route('**/api/**', async (route) => {
    const request = route.request()
    const pathname = new URL(request.url()).pathname
    const key = `${request.method()} ${pathname}`

    switch (key) {
      case 'GET /api/auth/session':
        await fulfillJSON(route, { enabled: false, authenticated: true })
        return
      case 'GET /api/inventory':
        options.onInventoryGet?.()
        await fulfillJSON(route, inventorySnapshot)
        return
      case 'GET /api/devices/device-nas/ssh-credential': {
        await fulfillJSON(
          route,
          {
            deviceId: 'device-nas',
            username: '',
            hasPassword: false,
            keyVersion: 2,
            sshPort: '22',
            available: true,
          },
          200,
          { ETag: `"${currentSSHCredentialVersion}"` },
        )
        return
      }
      case 'PUT /api/devices/device-nas/ssh-credential': {
        const ifMatch = request.headers()['if-match'] ?? null
        options.onSSHCredentialPut?.(ifMatch)
        if (options.sshCredentialPutDelayMs) {
          await new Promise((resolve) => setTimeout(resolve, options.sshCredentialPutDelayMs))
        }
        if (shouldConflictSSHCredential) {
          shouldConflictSSHCredential = false
          expectedSSHCredentialVersion = options.sshCredentialConflictOnceVersion!
          currentSSHCredentialVersion = expectedSSHCredentialVersion
          updateSSHDeviceVersion(expectedSSHCredentialVersion)
          await fulfillJSON(
            route,
            { error: 'resource version no longer matches' },
            412,
            { ETag: `"${expectedSSHCredentialVersion}"` },
          )
          return
        }
        if (ifMatch !== `"${expectedSSHCredentialVersion}"`) {
          await fulfillJSON(
            route,
            { error: 'resource version no longer matches' },
            412,
            { ETag: `"${expectedSSHCredentialVersion}"` },
          )
          return
        }
        const savedVersion = expectedSSHCredentialVersion + 1
        expectedSSHCredentialVersion = savedVersion
        currentSSHCredentialVersion = savedVersion
        updateSSHDeviceVersion(savedVersion)
        await fulfillJSON(
          route,
          {
            deviceId: 'device-nas',
            username: 'root',
            hasPassword: true,
            keyVersion: 2,
            sshPort: '22',
            available: true,
          },
          200,
          { ETag: `"${savedVersion}"` },
        )
        return
      }
      default:
        unexpectedRequests.push(key)
        await fulfillJSON(route, { error: `Unexpected E2E API request: ${key}` }, 501)
    }
  })

  return unexpectedRequests
}

export async function emitMonitorScanEvent(page: Page, kind: string, data: unknown) {
  await page.evaluate(
    ({ eventKind, eventData }) => {
      const testWindow = window as Window & {
        __homeMeshEventSources?: Array<EventTarget & { readyState: number; url: string }>
      }
      const source = testWindow.__homeMeshEventSources
        ?.slice()
        .reverse()
        .find((candidate) => candidate.url.endsWith('/api/events') && candidate.readyState !== 2)
      if (!source) {
        throw new Error('Monitor EventSource was not created')
      }
      source.dispatchEvent(new MessageEvent('scan', {
        data: JSON.stringify({ kind: eventKind, data: eventData }),
      }))
    },
    { eventKind: kind, eventData: data },
  )
}
