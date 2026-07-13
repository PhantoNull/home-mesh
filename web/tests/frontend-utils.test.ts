import { describe, expect, it } from 'vitest'
import {
  getSafePanelLink,
  moveItemByOffset,
  normalizePanelURL,
  panelURLValidationError,
  parseBulkRefreshResponse,
  parseResourceVersionETag,
  resolveSSHCapability,
  statusClassName,
  topologyEntityKey,
  truncateTopologyLabel,
} from '../src/frontend-utils'

describe('panel URL safety', () => {
  it('accepts absolute HTTP and HTTPS URLs', () => {
    expect(normalizePanelURL(' https://router.home:8443/admin ')).toBe('https://router.home:8443/admin')
    expect(normalizePanelURL('http://192.168.1.1')).toBe('http://192.168.1.1/')
  })

  it('rejects unsafe, relative, and malformed URLs', () => {
    expect(normalizePanelURL('javascript:alert(1)')).toBeNull()
    expect(normalizePanelURL('data:text/html,test')).toBeNull()
    expect(normalizePanelURL('/admin')).toBeNull()
    expect(panelURLValidationError('router.home')).toMatch(/HTTP or HTTPS/)
  })

  it('never renders an unsafe stored panel link', () => {
    expect(getSafePanelLink({ panelLink: 'javascript:alert(1)' })).toBe('')
  })
})

describe('bulk refresh response validation', () => {
  const snapshot = {
    devices: [],
    networkNodes: [],
    networkSegments: [],
    relations: [],
    actions: [],
  }
  const summary = {
    checked: 0,
    updated: 0,
    online: 0,
    degraded: 0,
    offline: 0,
    unknown: 0,
    macResolved: 0,
    skipped: 0,
    partial: false,
  }

  it('accepts the backend contract', () => {
    expect(parseBulkRefreshResponse({ summary, snapshot })).toEqual({ summary, snapshot })
  })

  it('rejects incomplete responses', () => {
    expect(() => parseBulkRefreshResponse({ summary, snapshot: { devices: [] } })).toThrow(/invalid response/)
  })

  it('accepts an explicitly partial refresh', () => {
    const partial = { ...summary, skipped: 2, partial: true }
    expect(parseBulkRefreshResponse({ summary: partial, snapshot }).summary).toEqual(partial)
  })
})

describe('presentation helpers', () => {
  it('limits dynamic status classes', () => {
    expect(statusClassName('degraded')).toBe('degraded')
    expect(statusClassName('invented-status')).toBe('unknown')
  })

  it('moves inventory entries by one keyboard step', () => {
    expect(moveItemByOffset(['a', 'b', 'c'], 1, -1)).toEqual(['b', 'a', 'c'])
    expect(moveItemByOffset(['a', 'b', 'c'], 2, 1)).toEqual(['a', 'b', 'c'])
  })

  it('truncates fixed-width topology labels', () => {
    expect(truncateTopologyLabel('a very long topology label', 12)).toBe('a very lo...')
  })

  it('keeps duplicate IDs in different topology kinds distinct', () => {
    expect(topologyEntityKey('device', 'shared-id')).not.toBe(topologyEntityKey('networkNode', 'shared-id'))
  })
})

describe('SSH capability preflight', () => {
  const credential = {
    deviceId: 'device-1',
    username: 'admin',
    hasPassword: false,
    keyVersion: 1,
    sshPort: '22',
  }

  it('keeps compatibility with servers that omit capability fields', () => {
    expect(resolveSSHCapability(credential)).toEqual({ available: true, reason: null })
  })

  it('surfaces an unavailable capability reason', () => {
    expect(resolveSSHCapability({ ...credential, available: false, unavailableReason: 'Master key missing.' })).toEqual({
      available: false,
      reason: 'Master key missing.',
    })
  })
})

describe('resource version ETag parsing', () => {
  it('accepts only canonical positive strong version tags', () => {
    expect(parseResourceVersionETag('"42"')).toBe(42)
    expect(parseResourceVersionETag('W/"42"')).toBeNull()
    expect(parseResourceVersionETag('"042"')).toBeNull()
    expect(parseResourceVersionETag('"0"')).toBeNull()
    expect(parseResourceVersionETag(null)).toBeNull()
  })

  it('rejects versions that cannot be represented safely in JavaScript', () => {
    expect(parseResourceVersionETag('"9007199254740992"')).toBeNull()
  })
})
