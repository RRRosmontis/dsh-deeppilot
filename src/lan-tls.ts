import { createHash, createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto'
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { generate } from 'selfsigned'
import { formatLogLine } from './diagnostics.ts'

export { LAN_TLS_FINGERPRINT_PATTERN, isLanTlsFingerprint } from './pairing-qr.ts'

export const LAN_TLS_COMMON_NAME = 'dsh-deeppilot'
export const LAN_TLS_KEY_FILE = 'key.pem'
export const LAN_TLS_CERT_FILE = 'cert.pem'

/**
 * Leaf lifetime. Deliberately short: Apple has enforced a hard 825-day ceiling
 * on TLS server certificates since iOS 13 / macOS 10.15, and the check runs
 * inside the TLS stack — an over-long leaf is rejected before an app's
 * certificate challenge (and therefore its fingerprint pinning) ever runs, so
 * the phone reports a bare "-1200 secure connection failed". 397 days is the
 * current CA/B Forum maximum for publicly trusted leaves and stays well under
 * the Apple limit while keeping re-signing rare.
 */
const CERT_VALIDITY_MS = 397 * 24 * 60 * 60_000
/** Re-sign this far ahead of expiry so a long-running host never serves a stale leaf. */
const CERT_RENEW_LEAD_MS = 30 * 24 * 60 * 60_000

/** One `subjectAltName` entry. `ip` carries type 7, `value` the name types. */
interface AltNameEntry {
  type: 1 | 2 | 6 | 7
  value?: string
  ip?: string
}

export interface LanTlsIdentity {
  /** PKCS#8 PEM private key. Never logged or reported. */
  key: string
  /** Self-signed X.509 PEM leaf certificate. */
  cert: string
  /** Pinned by paired devices; changes only when the private key changes. */
  fingerprint: string
  /** Unix ms when the current leaf certificate expires. */
  notAfter: number
  /**
   * The private key was newly created. Devices that pinned the previous
   * identity can no longer connect and must pair again.
   */
  regenerated: boolean
  /** A fresh leaf was signed with the existing key; the fingerprint is unchanged. */
  resigned: boolean
}

/** Compute the pinned public-key fingerprint of a PEM certificate. */
export function spkiFingerprint(certPem: string): string {
  const der = createPublicKey(certPem).export({ type: 'spki', format: 'der' })
  return 'sha256:' + createHash('sha256').update(der).digest('base64url')
}

/**
 * Load the LAN listener's TLS identity from `dir`, creating or repairing it
 * as needed. The private key is the durable identity: it is created once and
 * reused for every subsequent certificate, so pinned devices survive
 * certificate renewals. Only a missing or unreadable key forces a new one.
 */
export async function loadOrCreateLanTlsIdentity(
  dir: string,
  now: number = Date.now(),
  altHosts: readonly string[] = [],
): Promise<LanTlsIdentity> {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const keyPath = join(dir, LAN_TLS_KEY_FILE)
  const certPath = join(dir, LAN_TLS_CERT_FILE)

  let key = await readPem(keyPath, (error) => {
    // 读失败（非 ENOENT）会被下面当成「密钥缺失」直接重建：已配对设备的
    // 固定指纹随即失效、必须重新配对。这个后果必须可见，否则用户只会看到
    // 手机突然不认证书，而电脑端毫无线索。
    console.log(formatLogLine('warn', 'LAN TLS private key unreadable, regenerating identity: ' + describeFileError(error)))
  })
  let regenerated = false
  if (key === undefined || !validPrivateKey(key)) {
    regenerated = true
    key = undefined
  }

  let cert = regenerated ? undefined : await readPem(certPath, (error) => {
    // 证书读失败可以只重签（密钥不变、指纹不变），仍是需要留痕的异常。
    console.log(formatLogLine('warn', 'LAN TLS certificate unreadable, re-signing with the existing key: ' + describeFileError(error)))
  })
  let resigned = false
  const existing = key !== undefined && cert !== undefined ? inspectCertificate(cert, key, now) : undefined
  if (existing === undefined) {
    const issued = await issueCertificate(key, now, altHosts)
    if (key === undefined) {
      key = pemFile(issued.key)
      await writePrivate(keyPath, key)
    } else {
      resigned = true
    }
    cert = pemFile(issued.cert)
    await writePrivate(certPath, cert)
  }
  if (key === undefined || cert === undefined) throw new Error('LAN TLS identity unavailable')

  return {
    key,
    cert,
    fingerprint: spkiFingerprint(cert),
    notAfter: existing ?? new X509Certificate(cert).validToDate.getTime(),
    regenerated,
    resigned,
  }
}

async function readPem(path: string, onError?: (error: unknown) => void): Promise<string | undefined> {
  try {
    const text = await readFile(path, 'utf8')
    return text.trim().length > 0 ? text : undefined
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    // 非 ENOENT 的读取失败交给调用方留痕；随后仍按「文件缺失」重建身份，
    // 保证插件能起来。错误消息只含路径与 errno，不含密钥内容。
    onError?.(error)
    return undefined
  }
}

/** 读失败的安全描述：文件名 + errno，不带文件内容。 */
function describeFileError(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | undefined)?.code
  const message = error instanceof Error ? error.message : String(error)
  return (typeof code === 'string' ? 'code=' + code + ' ' : '') + message.slice(0, 140)
}

function validPrivateKey(pem: string): boolean {
  try {
    const key = createPrivateKey(pem)
    return key.asymmetricKeyType === 'ec'
  } catch {
    return false
  }
}

/**
 * Return the certificate's expiry when it is usable with `keyPem`, or
 * `undefined` when it must be re-issued (malformed, wrong key, or expiring).
 */
function inspectCertificate(certPem: string, keyPem: string, now: number): number | undefined {
  try {
    const cert = new X509Certificate(certPem)
    const certSpki = cert.publicKey.export({ type: 'spki', format: 'der' })
    const keySpki = createPublicKey(createPrivateKey(keyPem)).export({ type: 'spki', format: 'der' })
    if (!certSpki.equals(keySpki)) return undefined
    const notAfter = cert.validToDate.getTime()
    const notBefore = cert.validFromDate.getTime()
    if (!(notBefore <= now && notAfter - CERT_RENEW_LEAD_MS > now)) return undefined
    // A still-valid leaf that outlives the Apple ceiling must be re-signed.
    // The key is untouched, so the pinned fingerprint does not change.
    if (notAfter - notBefore > CERT_VALIDITY_MS + 24 * 60 * 60_000) return undefined
    return notAfter
  } catch {
    return undefined
  }
}

/**
 * Build the `subjectAltName` table for every address the listener is
 * advertised under.
 *
 * Apple's TLS stack validates the requested host against the certificate before
 * the app gets to pin anything, so an `https://<ip>:<port>` endpoint needs that
 * IP in the SAN list rather than only in the common name.
 */
function altNameEntries(hosts: readonly string[]): AltNameEntry[] {
  const entries = new Map<string, AltNameEntry>()
  entries.set(`2:${LAN_TLS_COMMON_NAME}`, { type: 2, value: LAN_TLS_COMMON_NAME })
  for (const host of hosts) {
    const value = host.trim().replace(/^\[|\]$/g, '')
    if (value === '' || !/^[A-Za-z0-9.:-]+$/.test(value)) continue
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(':')
    entries.set(
      `${isIp ? 7 : 2}:${value}`,
      isIp ? { type: 7, ip: value } : { type: 2, value },
    )
  }
  return [...entries.values()]
}

async function issueCertificate(
  existingKey: string | undefined,
  now: number,
  altHosts: readonly string[] = [],
): Promise<{ key: string; cert: string }> {
  // Back-date slightly so a phone whose clock trails the computer still accepts a
  // certificate issued moments ago.
  const notBeforeDate = new Date(now - 5 * 60_000)
  const notAfterDate = new Date(now + CERT_VALIDITY_MS)
  const keyPair = existingKey === undefined
    ? undefined
    : {
        privateKey: createPrivateKey(existingKey).export({ type: 'pkcs8', format: 'pem' }) as string,
        publicKey: createPublicKey(existingKey).export({ type: 'spki', format: 'pem' }) as string,
      }
  const result = await generate(
    [{ name: 'commonName', value: LAN_TLS_COMMON_NAME }],
    {
      keyType: 'ec',
      curve: 'P-256',
      algorithm: 'sha256',
      notBeforeDate,
      notAfterDate,
      ...(keyPair ? { keyPair } : {}),
      extensions: [
        { name: 'basicConstraints', cA: false, critical: true },
        { name: 'keyUsage', digitalSignature: true, keyAgreement: true, critical: true },
        { name: 'extKeyUsage', serverAuth: true },
        { name: 'subjectAltName', altNames: altNameEntries(altHosts) },
      ],
    },
  )
  return { key: existingKey ?? result.private, cert: result.cert }
}

/** Exact on-disk form, so a freshly issued value equals its later reload. */
function pemFile(pem: string): string {
  return pem.replace(/\r\n/g, '\n').trimEnd() + '\n'
}

async function writePrivate(path: string, contents: string): Promise<void> {
  const tmp = `${path}.${process.pid}.tmp`
  try {
    await writeFile(tmp, contents, { mode: 0o600 })
    await rename(tmp, path)
  } catch (error) {
    await unlink(tmp).catch(() => {})
    throw error
  }
}
