/// <reference types="@cloudflare/workers-types" />
import { describe, expect, it } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { eventId, verifyEvent, type NostrEvent } from '../src/nostr';
import { verifyNip98 } from '../src/nip98';

const PRIV = '0'.repeat(63) + '1';
const PUB = bytesToHex(schnorr.getPublicKey(PRIV));

// 由参考实现 nostr-tools（privkey=1）签出的真实事件，
// 用于确认事件序列化与生态实现完全一致
const SPEC_EVENT: NostrEvent = {
  id: '22b09758f18767d990c408ea649882f8d35e3950695187400dccebd21268dfc3',
  pubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  content: '',
  kind: 27235,
  created_at: 1682327852,
  tags: [
    ['u', 'https://api.snort.social/api/v1/n5sp/list'],
    ['method', 'GET'],
  ],
  sig: '5b03facdef0f16a22762e15e9573d4101ad8c79dd97bcb30d3fd1e6200cd2f3d76a3f322997f09e72f26ef7ec1837228185d5a51462f0fe9e7a5a843cdd7286f',
};

function signedEvent(method: string, url: string, body?: string, overrides: Partial<NostrEvent> = {}): NostrEvent {
  const event: NostrEvent = {
    pubkey: PUB,
    created_at: Math.floor(Date.now() / 1000),
    kind: 27235,
    tags: [
      ['u', url],
      ['method', method],
    ],
    content: '',
    ...overrides,
  };
  if (body) event.tags.push(['payload', bytesToHex(sha256(new TextEncoder().encode(body)))]);
  event.sig = bytesToHex(schnorr.sign(eventId(event), PRIV));
  return event;
}

function authRequest(method: string, url: string, body?: string, overrides: Partial<NostrEvent> = {}): Request {
  const event = signedEvent(method, url, body, overrides);
  return new Request(url, {
    method,
    body: body ?? null,
    headers: { authorization: `Nostr ${btoa(JSON.stringify(event))}` },
  });
}

describe('eventId / verifyEvent', () => {
  it('matches the nostr-tools reference vector', () => {
    expect(eventId(SPEC_EVENT)).toBe(SPEC_EVENT.id);
    expect(verifyEvent(SPEC_EVENT)).toBe(true);
  });

  it('rejects a tampered event', () => {
    expect(verifyEvent({ ...SPEC_EVENT, content: 'hacked' })).toBe(false);
  });
});

describe('verifyNip98', () => {
  it('accepts a valid GET', async () => {
    const request = authRequest('GET', 'https://api.example.com/api/names');
    expect(await verifyNip98(request)).toBe(PUB);
  });

  it('accepts a valid POST with payload hash', async () => {
    const body = JSON.stringify({ name: 'alice', pubkey: PUB });
    const request = authRequest('POST', 'https://api.example.com/api/names', body);
    expect(await verifyNip98(request, new TextEncoder().encode(body))).toBe(PUB);
  });

  it('rejects when payload hash does not match body', async () => {
    const body = JSON.stringify({ name: 'alice', pubkey: PUB });
    const request = authRequest('POST', 'https://api.example.com/api/names', body);
    const other = JSON.stringify({ name: 'bob', pubkey: PUB });
    expect(await verifyNip98(request, new TextEncoder().encode(other))).toBeNull();
  });

  it('accepts a POST without a payload tag (NIP-98 SHOULD, nak omits it)', async () => {
    const body = JSON.stringify({ name: 'alice', pubkey: PUB });
    const request = authRequest('POST', 'https://api.example.com/api/names', body, {
      tags: [
        ['u', 'https://api.example.com/api/names'],
        ['method', 'POST'],
      ],
    });
    expect(await verifyNip98(request, new TextEncoder().encode(body))).toBe(PUB);
  });

  it('rejects a wrong method tag', async () => {
    const request = authRequest('GET', 'https://api.example.com/api/names', undefined, {
      tags: [
        ['u', 'https://api.example.com/api/names'],
        ['method', 'POST'],
      ],
    });
    expect(await verifyNip98(request)).toBeNull();
  });

  it('rejects a mismatched u tag', async () => {
    const request = authRequest('GET', 'https://api.example.com/api/names', undefined, {
      tags: [
        ['u', 'https://other.example.com/api/names'],
        ['method', 'GET'],
      ],
    });
    expect(await verifyNip98(request)).toBeNull();
  });

  it('rejects an expired event', async () => {
    const request = authRequest('GET', 'https://api.example.com/api/names', undefined, {
      created_at: Math.floor(Date.now() / 1000) - 300,
    });
    expect(await verifyNip98(request)).toBeNull();
  });

  it('rejects a wrong kind', async () => {
    const request = authRequest('GET', 'https://api.example.com/api/names', undefined, { kind: 1 });
    expect(await verifyNip98(request)).toBeNull();
  });

  it('rejects a missing or malformed header', async () => {
    const noHeader = new Request('https://api.example.com/api/names');
    expect(await verifyNip98(noHeader)).toBeNull();
    const bad = new Request('https://api.example.com/api/names', {
      headers: { authorization: 'Nostr not-base64' },
    });
    expect(await verifyNip98(bad)).toBeNull();
  });

  it('treats host case in the u tag as insignificant', async () => {
    const request = authRequest('GET', 'https://api.example.com/api/names');
    const uppercaseHost = new Request('https://API.EXAMPLE.com/api/names', {
      method: 'GET',
      headers: { authorization: request.headers.get('authorization')! },
    });
    expect(await verifyNip98(uppercaseHost)).toBe(PUB);
  });

  it('accepts an uppercase-hex pubkey and returns it lowercase', async () => {
    const event = signedEvent('GET', 'https://api.example.com/api/names');
    event.pubkey = PUB.toUpperCase();
    event.sig = bytesToHex(schnorr.sign(eventId(event), PRIV));
    const request = new Request('https://api.example.com/api/names', {
      method: 'GET',
      headers: { authorization: `Nostr ${btoa(JSON.stringify(event))}` },
    });
    expect(await verifyNip98(request)).toBe(PUB);
  });
});
