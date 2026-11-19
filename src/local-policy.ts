export const DEFAULT_LOCAL_PORT = 3098
export const MIN_LOCAL_PORT = 1024
export const MAX_LOCAL_PORT = 65_535

export function normalizeLocalPort(value: unknown): number {
  return typeof value === 'number'
    && Number.isInteger(value)
    && value >= MIN_LOCAL_PORT
    && value <= MAX_LOCAL_PORT
    ? value
    : DEFAULT_LOCAL_PORT
}

/**
 * Normalize an operator-configured public endpoint to `https://host[:port]`.
 *
 * The LAN listener is TLS-only, and a port mapping or reverse tunnel may
 * terminate on a different host and port than the LAN address, so a configured
 * endpoint keeps its own authority. Only `https` is accepted: the app refuses
 * plaintext transports anyway, and credentials must never reach a pairing
 * payload.
 */
export function normalizePublicEndpoint(value: unknown): string | undefined {
  const trimmed = typeof value === 'string' ? value.trim() : ''
  if (trimmed === '') return undefined
  try {
    const url = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`)
    if (url.protocol !== 'https:') return undefined
    if (url.hostname === '' || url.username !== '' || url.password !== '') return undefined
    return `https://${url.host}`
  } catch {
    return undefined
  }
}

/** The LAN listener is TLS-only, so every advertised endpoint is `https://`. */
export function localEndpointURLs(addresses: readonly string[], port: number): string[] {
  const normalizedPort = normalizeLocalPort(port)
  // A configured public endpoint already carries its own authority.
  return [...new Set(addresses)].map((address) => address.startsWith('https://')
    ? address
    : `https://${address}:${normalizedPort}`)
}

export function localListenError(error: unknown, port: number): string {
  const code = (error as NodeJS.ErrnoException | undefined)?.code
  if (code === 'EADDRINUSE') return `local port ${port} is already in use`
  if (code === 'EACCES') return `permission denied while opening local port ${port}`
  return error instanceof Error ? error.message : String(error)
}
