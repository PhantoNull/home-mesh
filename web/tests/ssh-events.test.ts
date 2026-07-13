import { describe, expect, it } from 'vitest'
import { parseSSHServerMessage } from '../src/ssh-events'

describe('SSH terminal server messages', () => {
  it('accepts output and status messages', () => {
    expect(parseSSHServerMessage('{"type":"output","data":"ready\\n"}')).toEqual({ type: 'output', data: 'ready\n' })
    expect(parseSSHServerMessage('{"type":"pong"}')).toEqual({ type: 'pong' })
  })

  it('rejects malformed and unknown messages', () => {
    expect(() => parseSSHServerMessage('{bad')).toThrow(/malformed JSON/)
    expect(() => parseSSHServerMessage('{"type":"execute"}')).toThrow(/unknown message type/)
    expect(() => parseSSHServerMessage('{"type":"output","data":12}')).toThrow(/invalid message payload/)
  })
})
