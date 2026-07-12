import type { InventorySnapshot, SSHCredential } from './models'

export type RefreshSummary = {
  checked: number
  updated: number
  online: number
  degraded: number
  offline: number
  unknown: number
  macResolved: number
  skipped: number
  partial: boolean
}

export type BulkRefreshResponse = {
  summary: RefreshSummary
  snapshot: InventorySnapshot
}

const knownStatusClasses = new Set([
  'completed',
  'degraded',
  'failed',
  'mapped',
  'offline',
  'online',
  'running',
  'unknown',
])

export function normalizePanelURL(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }

  try {
    const parsed = new URL(trimmed)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null
    }
    return parsed.href
  } catch {
    return null
  }
}

export function getSafePanelLink(metadata?: Record<string, string>): string {
  return normalizePanelURL(metadata?.panelLink ?? '') ?? ''
}

export function panelURLValidationError(value: string): string | null {
  if (!value.trim() || normalizePanelURL(value)) {
    return null
  }
  return 'Panel URL must be an absolute HTTP or HTTPS URL.'
}

export function statusClassName(status: string): string {
  const normalized = status.trim().toLowerCase()
  return knownStatusClasses.has(normalized) ? normalized : 'unknown'
}

export function moveItemByOffset<T>(items: T[], index: number, offset: -1 | 1): T[] {
  const target = index + offset
  if (index < 0 || index >= items.length || target < 0 || target >= items.length) {
    return items
  }

  const next = [...items]
  const [item] = next.splice(index, 1)
  next.splice(target, 0, item)
  return next
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isInventorySnapshot(value: unknown): value is InventorySnapshot {
  if (!isRecord(value)) {
    return false
  }
  return (
    Array.isArray(value.devices) &&
    Array.isArray(value.networkNodes) &&
    Array.isArray(value.networkSegments) &&
    Array.isArray(value.relations) &&
    Array.isArray(value.actions)
  )
}

function isRefreshSummary(value: unknown): value is RefreshSummary {
  if (!isRecord(value)) {
    return false
  }
  return (
    ['checked', 'updated', 'online', 'degraded', 'offline', 'unknown', 'macResolved', 'skipped'].every(
      (key) => typeof value[key] === 'number' && Number.isFinite(value[key]),
    ) && typeof value.partial === 'boolean'
  )
}

export function parseBulkRefreshResponse(value: unknown): BulkRefreshResponse {
  if (!isRecord(value) || !isRefreshSummary(value.summary) || !isInventorySnapshot(value.snapshot)) {
    throw new Error('Refresh endpoint returned an invalid response.')
  }

  return {
    summary: value.summary,
    snapshot: value.snapshot,
  }
}

export function parseResourceVersionETag(value: string | null): number | null {
  const match = /^"([1-9]\d*)"$/.exec(value ?? '')
  if (!match) {
    return null
  }

  const version = Number(match[1])
  return Number.isSafeInteger(version) ? version : null
}

export function truncateTopologyLabel(value: string, maxLength = 24): string {
  if (value.length <= maxLength) {
    return value
  }
  return `${value.slice(0, Math.max(0, maxLength - 3))}...`
}

export function topologyEntityKey(kind: string, id: string): string {
  return `${kind}\u001f${id}`
}

export function resolveSSHCapability(credential: SSHCredential): { available: boolean; reason: string | null } {
  const available = credential.available !== false
  return {
    available,
    reason: available
      ? null
      : credential.unavailableReason?.trim() ||
        'SSH is unavailable because encrypted credential storage is not configured.',
  }
}
