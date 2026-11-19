import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DEFAULT_LOCAL_PORT,
  localEndpointURLs,
  localListenError,
  normalizeLocalPort,
  normalizePublicEndpoint,
} from '../src/local-policy.ts'

test('local port normalization keeps a stable cross-platform default', () => {
  assert.equal(normalizeLocalPort(undefined), DEFAULT_LOCAL_PORT)
  assert.equal(normalizeLocalPort(3098), 3098)
  assert.equal(normalizeLocalPort(65_535), 65_535)
  assert.equal(normalizeLocalPort(1023), DEFAULT_LOCAL_PORT)
  assert.equal(normalizeLocalPort(3098.5), DEFAULT_LOCAL_PORT)
})

test('local endpoints are TLS-only, use the independent port and remove duplicate addresses', () => {
  assert.deepEqual(
    localEndpointURLs(['192.168.1.149', '10.0.0.8', '192.168.1.149'], 3098),
    ['https://192.168.1.149:3098', 'https://10.0.0.8:3098'],
  )
})

test('a configured public endpoint keeps its own authority instead of the LAN port', () => {
  // Port mappings and reverse tunnels terminate on a different host/port.
  assert.deepEqual(
    localEndpointURLs(['192.168.1.149', 'https://pilot.example.com'], 3098),
    ['https://192.168.1.149:3098', 'https://pilot.example.com'],
  )
  assert.deepEqual(
    localEndpointURLs(['https://203.0.113.7:41234'], 3098),
    ['https://203.0.113.7:41234'],
  )
})

test('public endpoints are normalized to https authority only', () => {
  assert.equal(normalizePublicEndpoint('pilot.example.com'), 'https://pilot.example.com')
  assert.equal(normalizePublicEndpoint('  https://203.0.113.7:41234/  '), 'https://203.0.113.7:41234')
  assert.equal(normalizePublicEndpoint('https://[2001:db8::1]:443'), 'https://[2001:db8::1]')
  // Plaintext, credentials and junk must never reach a pairing payload.
  assert.equal(normalizePublicEndpoint('http://pilot.example.com'), undefined)
  assert.equal(normalizePublicEndpoint('https://user:pass@pilot.example.com'), undefined)
  assert.equal(normalizePublicEndpoint(''), undefined)
  assert.equal(normalizePublicEndpoint(undefined), undefined)
  assert.equal(normalizePublicEndpoint(42), undefined)
})

test('local listen errors explain common port failures', () => {
  const inUse = Object.assign(new Error('bind failed'), { code: 'EADDRINUSE' })
  assert.equal(localListenError(inUse, 3098), 'local port 3098 is already in use')
  assert.equal(localListenError(new Error('other failure'), 3098), 'other failure')
})
