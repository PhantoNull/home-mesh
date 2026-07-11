import { describe, expect, it } from 'vitest'
import {
  parseDiscoveryCompleteEvent,
  parseDiscoveryErrorEvent,
  parseDiscoveryHostEvent,
} from '../src/discovery-events'

describe('discovery event payloads', () => {
  it('parses a discovery host update', () => {
    const host = parseDiscoveryHostEvent('{"ipAddress":"192.168.1.20","hostname":"nas.home"}')

    expect(host).toEqual({ ipAddress: '192.168.1.20', hostname: 'nas.home' })
  })

  it('rejects malformed discovery host JSON', () => {
    expect(() => parseDiscoveryHostEvent('{not-json')).toThrow(
      'Discovery stream sent an invalid host update.',
    )
  })

  it('normalizes an omitted segment candidate collection', () => {
    const result = parseDiscoveryCompleteEvent(
      '{"provider":"nmap","cidr":"192.168.1.0/24","scannedCidrs":["192.168.1.0/24"],"hosts":[]}',
    )

    expect(result.segmentCandidates).toEqual([])
  })

  it('parses segment candidates from a completion event', () => {
    const result = parseDiscoveryCompleteEvent(
      JSON.stringify({
        provider: 'nmap',
        cidr: '192.168.1.0/24',
        scannedCidrs: ['192.168.1.0/24'],
        hosts: [],
        segmentCandidates: [{ cidr: '192.168.1.0/24', name: 'Local network' }],
      }),
    )

    expect(result.segmentCandidates).toEqual([
      { cidr: '192.168.1.0/24', name: 'Local network' },
    ])
  })

  it('rejects an invalid completion payload', () => {
    expect(() => parseDiscoveryCompleteEvent('{"provider":"nmap","hosts":[]}')).toThrow(
      'Discovery stream sent an invalid completion response.',
    )
  })

  it('rejects an invalid segment candidate', () => {
    expect(() =>
      parseDiscoveryCompleteEvent(
        JSON.stringify({
          provider: 'nmap',
          cidr: '192.168.1.0/24',
          scannedCidrs: ['192.168.1.0/24'],
          hosts: [],
          segmentCandidates: [{ cidr: '192.168.1.0/24' }],
        }),
      ),
    ).toThrow('Discovery stream sent an invalid completion response.')
  })

  it('rejects a discovery error event without a message', () => {
    expect(() => parseDiscoveryErrorEvent('{}')).toThrow(
      'Discovery stream sent an invalid error response.',
    )
  })
})
