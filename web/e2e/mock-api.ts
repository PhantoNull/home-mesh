import type { Page, Route } from '@playwright/test'
import type { InventorySnapshot } from '../src/models'

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

async function fulfillJSON(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  })
}

export async function installDeterministicMocks(page: Page): Promise<string[]> {
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
        await fulfillJSON(route, inventoryFixture)
        return
      default:
        unexpectedRequests.push(key)
        await fulfillJSON(route, { error: `Unexpected E2E API request: ${key}` }, 501)
    }
  })

  return unexpectedRequests
}
