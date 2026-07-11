export type SSHServerMessage = {
  type: 'output' | 'status' | 'error' | 'pong'
  data?: string
}

const messageTypes = new Set<SSHServerMessage['type']>(['output', 'status', 'error', 'pong'])

export function parseSSHServerMessage(value: unknown): SSHServerMessage {
  if (typeof value !== 'string') {
    throw new Error('SSH terminal received a non-text message.')
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    throw new Error('SSH terminal received malformed JSON.')
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('SSH terminal received an invalid message.')
  }

  const record = parsed as Record<string, unknown>
  if (typeof record.type !== 'string' || !messageTypes.has(record.type as SSHServerMessage['type'])) {
    throw new Error('SSH terminal received an unknown message type.')
  }
  if (record.data !== undefined && typeof record.data !== 'string') {
    throw new Error('SSH terminal received an invalid message payload.')
  }

  return {
    type: record.type as SSHServerMessage['type'],
    ...(typeof record.data === 'string' ? { data: record.data } : {}),
  }
}
