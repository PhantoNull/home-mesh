import type { DiscoveryHostMatch, DiscoveryScanResult } from './models'

function parseDiscoveryRecord(data: string, errorMessage: string): Record<string, unknown> {
  let value: unknown
  try {
    value = JSON.parse(data)
  } catch {
    throw new Error(errorMessage)
  }

  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(errorMessage)
  }

  return value as Record<string, unknown>
}

function discoveryHostFromRecord(value: unknown, errorMessage: string): DiscoveryHostMatch {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(errorMessage)
  }

  const record = value as Record<string, unknown>
  if (typeof record.ipAddress !== 'string' || !record.ipAddress.trim()) {
    throw new Error(errorMessage)
  }

  return {
    ipAddress: record.ipAddress.trim(),
    ...(typeof record.hostname === 'string' ? { hostname: record.hostname } : {}),
    ...(typeof record.macAddress === 'string' ? { macAddress: record.macAddress } : {}),
    ...(typeof record.vendor === 'string' ? { vendor: record.vendor } : {}),
  }
}

export function parseDiscoveryHostEvent(data: string): DiscoveryHostMatch {
  const errorMessage = 'Discovery stream sent an invalid host update.'
  return discoveryHostFromRecord(parseDiscoveryRecord(data, errorMessage), errorMessage)
}

export function parseDiscoveryCompleteEvent(data: string): DiscoveryScanResult {
  const errorMessage = 'Discovery stream sent an invalid completion response.'
  const record = parseDiscoveryRecord(data, errorMessage)

  if (
    typeof record.provider !== 'string' ||
    typeof record.cidr !== 'string' ||
    !Array.isArray(record.scannedCidrs) ||
    record.scannedCidrs.some((cidr) => typeof cidr !== 'string') ||
    !Array.isArray(record.hosts)
  ) {
    throw new Error(errorMessage)
  }

  const segmentCandidates = record.segmentCandidates ?? []
  if (!Array.isArray(segmentCandidates)) {
    throw new Error(errorMessage)
  }

  return {
    provider: record.provider,
    cidr: record.cidr,
    scannedCidrs: record.scannedCidrs as string[],
    hosts: record.hosts.map((host) => discoveryHostFromRecord(host, errorMessage)),
    segmentCandidates: segmentCandidates.map((candidate) => {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
        throw new Error(errorMessage)
      }
      const candidateRecord = candidate as Record<string, unknown>
      if (typeof candidateRecord.cidr !== 'string' || typeof candidateRecord.name !== 'string') {
        throw new Error(errorMessage)
      }
      return { cidr: candidateRecord.cidr, name: candidateRecord.name }
    }),
  }
}

export function parseDiscoveryErrorEvent(data: string): string {
  const errorMessage = 'Discovery stream sent an invalid error response.'
  const record = parseDiscoveryRecord(data, errorMessage)
  if (typeof record.error !== 'string' || !record.error.trim()) {
    throw new Error(errorMessage)
  }
  return record.error
}
