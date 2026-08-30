import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'
import type { InventorySnapshot } from '../src/models'
import { emitMonitorScanEvent, installDeterministicMocks, inventoryFixture } from './mock-api'

type RuntimeErrors = {
  console: string[]
  page: string[]
}

function monitorRuntimeErrors(page: Page): RuntimeErrors {
  const errors: RuntimeErrors = { console: [], page: [] }
  page.on('console', (message) => {
    if (message.type() === 'error') {
      errors.console.push(message.text())
    }
  })
  page.on('pageerror', (error) => errors.page.push(error.message))
  return errors
}

async function openDashboard(page: Page) {
  const runtimeErrors = monitorRuntimeErrors(page)
  const unexpectedRequests = await installDeterministicMocks(page)

  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1, name: 'Home Mesh' })).toBeVisible()
  await expect(page.locator('#inventory-panel-devices').getByText('NAS Alpha', { exact: true })).toBeVisible()

  return { runtimeErrors, unexpectedRequests }
}

async function expectNoDocumentOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    body: document.body.scrollWidth,
    document: document.documentElement.scrollWidth,
    viewport: document.documentElement.clientWidth,
  }))

  expect(dimensions.document, `document width ${dimensions.document}px exceeds ${dimensions.viewport}px`).toBeLessThanOrEqual(dimensions.viewport + 1)
  expect(dimensions.body, `body width ${dimensions.body}px exceeds ${dimensions.viewport}px`).toBeLessThanOrEqual(dimensions.viewport + 1)
}

async function expectNoAxeViolations(page: Page) {
  const result = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze()
  const summary = result.violations.map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    help: violation.help,
    targets: violation.nodes.map((node) => node.target),
  }))

  expect(result.violations, JSON.stringify(summary, null, 2)).toEqual([])
}

function denseTopologyFixture(entityCount: number): InventorySnapshot {
  const nodeCount = Math.max(1, Math.floor(entityCount / 10))
  const deviceCount = entityCount - nodeCount - 1
  const networkNodes = Array.from({ length: nodeCount }, (_, index) => ({
    id: `node-${index}`,
    version: 1,
    name: `Access switch ${index}`,
    nodeType: 'switch',
    managementIp: `10.0.0.${index + 1}`,
    macAddress: '',
    vendor: 'Home Mesh Labs',
    model: 'HM-S24',
    status: index % 12 === 0 ? 'degraded' : 'online',
    tags: ['access'],
  }))
  const devices = Array.from({ length: deviceCount }, (_, index) => ({
    id: `device-${index}`,
    version: 1,
    name: `Endpoint ${index}`,
    hostname: `endpoint-${index}.home.arpa`,
    role: 'workstation',
    deviceType: 'desktop',
    ipAddress: `10.${Math.floor(index / 254) + 1}.0.${(index % 254) + 1}`,
    macAddress: '',
    networkSegment: 'segment-main',
    status: index % 17 === 0 ? 'offline' : 'online',
    tags: ['managed'],
  }))
  return {
    devices,
    networkNodes,
    networkSegments: [{
      id: 'segment-main',
      version: 1,
      name: 'Managed LAN',
      segmentType: 'lan',
      cidr: '10.0.0.0/8',
      vlanId: 10,
      gatewayIp: '10.0.0.1',
      dnsDomain: 'home.arpa',
    }],
    relations: [
      ...networkNodes.map((node) => ({
        id: `segment-${node.id}`,
        version: 1,
        sourceKind: 'networkSegment',
        sourceId: 'segment-main',
        targetKind: 'networkNode',
        targetId: node.id,
        relationType: 'routed_by',
        confidence: 'observed',
      })),
      ...devices.map((device, index) => ({
        id: `node-device-${index}`,
        version: 1,
        sourceKind: 'networkNode',
        sourceId: networkNodes[index % networkNodes.length].id,
        targetKind: 'device',
        targetId: device.id,
        relationType: 'connected_to',
        confidence: 'observed',
      })),
    ],
    actions: [],
  }
}

test('renders the mocked inventory without browser or API errors', async ({ page }) => {
  const { runtimeErrors, unexpectedRequests } = await openDashboard(page)

  await expect(page.getByText('Endpoint devices').locator('..').getByText('1', { exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { level: 2, name: 'Devices' })).toBeVisible()
  await expect(page.getByRole('heading', { level: 2, name: 'Network nodes' })).toBeVisible()
  await expect(page.getByRole('heading', { level: 2, name: 'Network segments' })).toBeVisible()
  await expect(page.getByRole('region', { name: 'Interactive network topology' })).toBeVisible()
  await expect(page.getByRole('status', { name: '' }).filter({ hasText: 'Live: on' })).toBeVisible()

  expect(unexpectedRequests).toEqual([])
  expect(runtimeErrors.console).toEqual([])
  expect(runtimeErrors.page).toEqual([])
})

test('focuses topology paths and exposes stable view controls', async ({ page }) => {
  const { runtimeErrors, unexpectedRequests } = await openDashboard(page)

  const graph = page.getByRole('region', { name: 'Interactive network topology' })
  const explorer = page.getByRole('complementary', { name: 'Topology explorer' })
  const inspector = page.getByRole('complementary', { name: 'Selected topology entity' })
  await expect(page.locator('.topology-layout-state')).toBeHidden()
  await expect(page.getByLabel('Topology summary')).toContainText('3 entities')
  await expect(page.getByLabel('Topology summary')).toContainText('2 links')

  const device = explorer.getByRole('button', { name: /NAS Alpha/ })
  await device.click()
  await expect(device).toHaveAttribute('aria-pressed', 'true')
  await expect(inspector.getByRole('heading', { level: 3, name: 'NAS Alpha' })).toBeVisible()
  await expect(graph.locator('.react-flow__node.selected')).toContainText('NAS Alpha')

  const viewport = graph.locator('.react-flow__viewport')
  const initialTransform = await viewport.getAttribute('style')
  const zoomIn = graph.locator('.react-flow__controls-zoomin')
  await expect(zoomIn).toBeEnabled()
  await expect(graph.locator('.react-flow__controls-zoomout')).toBeEnabled()
  await expect(graph.locator('.react-flow__controls-fitview')).toBeEnabled()
  await zoomIn.click()
  await expect.poll(() => viewport.getAttribute('style')).not.toBe(initialTransform)
  const zoomedTransform = await viewport.getAttribute('style')

  const pane = graph.locator('.react-flow__pane')
  const paneBox = await pane.boundingBox()
  expect(paneBox).not.toBeNull()
  await page.mouse.move(paneBox!.x + 24, paneBox!.y + 24)
  await page.mouse.down()
  await page.mouse.move(paneBox!.x + 64, paneBox!.y + 54)
  await page.mouse.up()
  await expect.poll(() => viewport.getAttribute('style')).not.toBe(zoomedTransform)
  const pannedTransform = await viewport.getAttribute('style')
  await graph.locator('.react-flow__controls-fitview').click()
  await expect.poll(() => viewport.getAttribute('style')).not.toBe(pannedTransform)

  const verticalLayout = page.getByRole('button', { name: 'Use vertical topology layout' })
  await verticalLayout.click()
  await expect(verticalLayout).toHaveAttribute('aria-pressed', 'true')
  await expect(page.locator('.topology-layout-state')).toBeHidden()

  const labelsToggle = page.getByRole('button', { name: 'Toggle relation labels' })
  await labelsToggle.click()
  await expect(labelsToggle).toHaveAttribute('aria-pressed', 'false')

  const search = explorer.getByRole('textbox', { name: 'Search topology' })
  await search.fill('192.168.10.20')
  await expect(explorer.getByText('1/3')).toBeVisible()
  await explorer.getByRole('button', { name: 'Clear topology search' }).click()
  await expect(explorer.getByText('3/3')).toBeVisible()

  const graphDevice = graph.getByRole('button', { name: /Device NAS Alpha/ })
  await graphDevice.focus()
  await graphDevice.press('Enter')
  await expect(inspector.getByRole('heading', { level: 3, name: 'NAS Alpha' })).toBeVisible()

  expect(unexpectedRequests).toEqual([])
  expect(runtimeErrors.console).toEqual([])
  expect(runtimeErrors.page).toEqual([])
})

test('preserves topology selection and viewport during a live status update', async ({ page }) => {
  const { runtimeErrors, unexpectedRequests } = await openDashboard(page)
  const graph = page.getByRole('region', { name: 'Interactive network topology' })
  const explorer = page.getByRole('complementary', { name: 'Topology explorer' })
  await expect(page.locator('.topology-layout-state')).toBeHidden()
  await page.waitForTimeout(400)
  await explorer.getByRole('button', { name: /NAS Alpha/ }).click()

  const graphDevice = graph.getByRole('button', { name: /Device NAS Alpha/ })
  const viewportBefore = await graph.locator('.react-flow__viewport').getAttribute('style')
  const positionBefore = await graphDevice.getAttribute('style')
  await emitMonitorScanEvent(page, 'device-updated', {
    ...inventoryFixture.devices[0],
    version: 4,
    status: 'degraded',
  })

  await expect(graphDevice).toContainText('degraded')
  await expect(page.getByRole('complementary', { name: 'Selected topology entity' })).toContainText('degraded')
  await expect(graph.locator('.react-flow__viewport')).toHaveAttribute('style', viewportBefore ?? '')
  await expect(graphDevice).toHaveAttribute('style', positionBefore ?? '')
  expect(unexpectedRequests).toEqual([])
  expect(runtimeErrors.console).toEqual([])
  expect(runtimeErrors.page).toEqual([])
})

test('makes 250 entities interactive within budget and completes layout', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-chromium', 'Scale timing runs once on desktop Chromium.')
  const runtimeErrors = monitorRuntimeErrors(page)
  const unexpectedRequests = await installDeterministicMocks(page, { inventory: denseTopologyFixture(250) })

  await page.goto('/')
  const workspace = page.locator('.topology-workspace')
  await expect(workspace.getByLabel('Topology summary')).toContainText('250 entities')
  await expect(page.getByRole('region', { name: 'Interactive network topology' }).locator('.react-flow__controls-zoomin')).toBeEnabled()
  const interactiveAt = Number(await workspace.getAttribute('data-interactive-at-ms'))
  expect(interactiveAt).toBeGreaterThan(0)
  expect(interactiveAt).toBeLessThan(2_000)
  await expect(page.locator('.topology-layout-state')).toBeHidden({ timeout: 8_000 })
  expect(unexpectedRequests).toEqual([])
  expect(runtimeErrors.console).toEqual([])
  expect(runtimeErrors.page).toEqual([])
})

test('keeps a 1000-entity topology usable through search and label suppression', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-chromium', 'Large-graph behavior runs once on desktop Chromium.')
  const runtimeErrors = monitorRuntimeErrors(page)
  const unexpectedRequests = await installDeterministicMocks(page, { inventory: denseTopologyFixture(1_000) })

  await page.goto('/')
  await expect(page.getByLabel('Topology summary')).toContainText('1000 entities')
  await expect(page.getByText('Relation labels are shown on selection for this graph size.')).toBeVisible()
  await expect(page.getByText('Fast grouped layout is active for this graph size.')).toBeVisible()
  await expect(page.getByText('The canvas shows the first 300 of 1000 matches. Refine search or filters to inspect the rest.')).toBeVisible()
  const explorer = page.getByRole('complementary', { name: 'Topology explorer' })
  await explorer.getByRole('textbox', { name: 'Search topology' }).fill('endpoint-898.home.arpa')
  await expect(explorer.getByText('1/1000')).toBeVisible()
  await expect(page.getByRole('region', { name: 'Interactive network topology' }).locator('.react-flow__edge-text')).toHaveCount(0)
  await expect(page.locator('.topology-layout-state')).toBeHidden({ timeout: 10_000 })
  expect(unexpectedRequests).toEqual([])
  expect(runtimeErrors.console).toEqual([])
  expect(runtimeErrors.page).toEqual([])
})

test('saves SSH credentials against the latest credential and monitor device version', async ({ page }) => {
  const runtimeErrors = monitorRuntimeErrors(page)
  const submittedIfMatches: Array<string | null> = []
  const unexpectedRequests = await installDeterministicMocks(page, {
    sshCredentialDeviceVersion: 4,
    sshCredentialExpectedPutVersion: 5,
    onSSHCredentialPut: (ifMatch) => submittedIfMatches.push(ifMatch),
  })

  await page.goto('/')
  await expect(page.locator('#inventory-panel-devices').getByText('NAS Alpha', { exact: true })).toBeVisible()
  await page.locator('#inventory-panel-devices').getByRole('button', { name: 'SSH' }).click()

  const dialog = page.getByRole('dialog', { name: 'NAS Alpha' })
  await expect(dialog).toBeVisible()
  await emitMonitorScanEvent(page, 'device-updated', {
    ...inventoryFixture.devices[0],
    version: 5,
    status: 'degraded',
  })
  await dialog.getByLabel('SSH username').fill('root')
  await dialog.getByLabel('SSH password').fill('secret-password')
  await dialog.getByRole('button', { name: 'Save SSH credentials' }).click()

  await expect.poll(() => submittedIfMatches).toEqual(['"5"'])
  await expect(page.getByText('SSH credentials saved for NAS Alpha.')).toBeVisible()
  expect(unexpectedRequests).toEqual([])
  expect(runtimeErrors.console).toEqual([])
  expect(runtimeErrors.page).toEqual([])
})

test('probes and explicitly approves an unknown SSH host key', async ({ page }) => {
  const unexpectedRequests = await installDeterministicMocks(page)

  await page.goto('/')
  await page.locator('#inventory-panel-devices').getByRole('button', { name: 'SSH' }).click()
  const dialog = page.getByRole('dialog', { name: 'NAS Alpha' })
  await dialog.getByLabel('SSH username').fill('root')
  await dialog.getByLabel('SSH password').fill('secret-password')
  await dialog.getByRole('button', { name: 'Save SSH credentials' }).click()

  await dialog.getByRole('button', { name: 'Check host key' }).click()
  await expect(dialog.locator('.ssh-host-key-fingerprint')).toHaveText('SHA256:fixture-host-key')
  await dialog.getByRole('button', { name: 'Trust this host key' }).click()
  await expect(dialog.locator('.ssh-host-key-panel')).toContainText('Host key trusted')
  expect(unexpectedRequests).toEqual([])
})

test('rebases an SSH credential form after a concurrent device change', async ({ page }) => {
  const submittedIfMatches: Array<string | null> = []
  const unexpectedRequests = await installDeterministicMocks(page, {
    sshCredentialDeviceVersion: 4,
    sshCredentialConflictOnceVersion: 5,
    onSSHCredentialPut: (ifMatch) => submittedIfMatches.push(ifMatch),
  })

  await page.goto('/')
  await expect(page.locator('#inventory-panel-devices').getByText('NAS Alpha', { exact: true })).toBeVisible()
  await page.locator('#inventory-panel-devices').getByRole('button', { name: 'SSH' }).click()

  const dialog = page.getByRole('dialog', { name: 'NAS Alpha' })
  await dialog.getByLabel('SSH username').fill('root')
  await dialog.getByLabel('SSH password').fill('secret-password')
  await dialog.getByRole('button', { name: 'Save SSH credentials' }).click()

  await expect(dialog.getByRole('alert')).toContainText('Device changed while you were editing')
  await expect(dialog.getByLabel('SSH password')).toHaveValue('secret-password')
  await dialog.getByRole('button', { name: 'Save SSH credentials' }).click()

  await expect(page.getByText('SSH credentials saved for NAS Alpha.')).toBeVisible()
  expect(submittedIfMatches).toEqual(['"4"', '"5"'])
  expect(unexpectedRequests).toEqual([])
})

test('refreshes global inventory when the SSH modal closes during a committed save', async ({ page }) => {
  const submittedIfMatches: Array<string | null> = []
  let inventoryGets = 0
  const unexpectedRequests = await installDeterministicMocks(page, {
    sshCredentialDeviceVersion: 4,
    sshCredentialPutDelayMs: 100,
    onSSHCredentialPut: (ifMatch) => submittedIfMatches.push(ifMatch),
    onInventoryGet: () => { inventoryGets += 1 },
  })

  await page.goto('/')
  await expect(page.locator('#inventory-panel-devices').getByText('NAS Alpha', { exact: true })).toBeVisible()
  await page.locator('#inventory-panel-devices').getByRole('button', { name: 'SSH' }).click()

  let dialog = page.getByRole('dialog', { name: 'NAS Alpha' })
  await dialog.getByLabel('SSH username').fill('root')
  await dialog.getByLabel('SSH password').fill('secret-password')
  await dialog.getByRole('button', { name: 'Save SSH credentials' }).click()
  await expect.poll(() => submittedIfMatches).toEqual(['"4"'])
  await dialog.getByRole('button', { name: 'Close NAS Alpha' }).click()
  await expect(dialog).toBeHidden()
  await expect.poll(() => inventoryGets).toBeGreaterThanOrEqual(2)

  await page.locator('#inventory-panel-devices').getByRole('button', { name: 'SSH' }).click()
  dialog = page.getByRole('dialog', { name: 'NAS Alpha' })
  await dialog.getByLabel('SSH username').fill('root')
  await dialog.getByLabel('SSH password').fill('second-password')
  await dialog.getByRole('button', { name: 'Save SSH credentials' }).click()

  await expect(page.getByText('SSH credentials saved for NAS Alpha.')).toBeVisible()
  expect(submittedIfMatches).toEqual(['"4"', '"5"'])
  expect(unexpectedRequests).toEqual([])
})

test('keeps the dashboard and its topology scroller inside the viewport', async ({ page }) => {
  await openDashboard(page)

  await expectNoDocumentOverflow(page)
  const topologyScroller = page.locator('.topology-workspace__canvas')
  await expect(topologyScroller).toBeVisible()
  const topologyOverflow = await topologyScroller.evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
  }))
  expect(topologyOverflow.scrollWidth).toBeLessThanOrEqual(topologyOverflow.clientWidth + 1)
})

test('traps modal focus, stays in the viewport, and restores focus on Escape', async ({ page }) => {
  await openDashboard(page)

  const trigger = page.getByRole('button', { name: 'Add device' })
  await trigger.click()

  const dialog = page.getByRole('dialog', { name: 'Create device' })
  const firstControl = dialog.getByRole('button', { name: 'Close Create device' })
  const lastControl = dialog.getByRole('button', { name: 'Create device', exact: true })
  await expect(dialog).toBeVisible()
  await expect(firstControl).toBeFocused()
  await expect(page.locator('body')).toHaveCSS('overflow', 'hidden')

  await page.keyboard.press('Shift+Tab')
  await expect(lastControl).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(firstControl).toBeFocused()

  const box = await dialog.boundingBox()
  const viewport = page.viewportSize()
  expect(box).not.toBeNull()
  expect(viewport).not.toBeNull()
  expect(box!.x).toBeGreaterThanOrEqual(0)
  expect(box!.y).toBeGreaterThanOrEqual(0)
  expect(box!.x + box!.width).toBeLessThanOrEqual(viewport!.width + 1)
  expect(box!.y + box!.height).toBeLessThanOrEqual(viewport!.height + 1)
  await expectNoDocumentOverflow(page)

  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await expect(trigger).toBeFocused()
  await expect(page.locator('body')).not.toHaveCSS('overflow', 'hidden')
})

test('meets WCAG A and AA checks on the dashboard and create modal', async ({ page }) => {
  await openDashboard(page)
  await expectNoAxeViolations(page)

  await page.getByRole('button', { name: 'Add device' }).click()
  await expect(page.getByRole('dialog', { name: 'Create device' })).toBeVisible()
  await expectNoAxeViolations(page)
})
