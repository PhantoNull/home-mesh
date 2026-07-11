import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'
import { installDeterministicMocks } from './mock-api'

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

test('renders the mocked inventory without browser or API errors', async ({ page }) => {
  const { runtimeErrors, unexpectedRequests } = await openDashboard(page)

  await expect(page.getByText('Endpoint devices').locator('..').getByText('1', { exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { level: 2, name: 'Devices' })).toBeVisible()
  await expect(page.getByRole('heading', { level: 2, name: 'Network nodes' })).toBeVisible()
  await expect(page.getByRole('heading', { level: 2, name: 'Network segments' })).toBeVisible()
  await expect(page.getByRole('img', { name: 'Network topology graph' })).toBeVisible()
  await expect(page.getByRole('status')).toContainText('Live: on')

  expect(unexpectedRequests).toEqual([])
  expect(runtimeErrors.console).toEqual([])
  expect(runtimeErrors.page).toEqual([])
})

test('keeps the dashboard and its topology scroller inside the viewport', async ({ page }) => {
  await openDashboard(page)

  await expectNoDocumentOverflow(page)
  const topologyScroller = page.locator('.topology-graph__canvas')
  await expect(topologyScroller).toBeVisible()
  const topologyOverflow = await topologyScroller.evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
  }))
  expect(topologyOverflow.scrollWidth).toBeGreaterThanOrEqual(topologyOverflow.clientWidth)
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
