import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { verifyEvent, type NostrEvent } from './nostr';

const AUTH_SCHEME = 'Nostr ';
const AUTH_KIND = 27235;
const MAX_AGE_SECONDS = 60;
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);

function parseAuthHeader(request: Request): NostrEvent | null {
  const header = request.headers.get('authorization');
  if (!header || !header.startsWith(AUTH_SCHEME)) return null;
  try {
    return JSON.parse(atob(header.slice(AUTH_SCHEME.length).trim()));
  } catch {
    return null;
  }
}

function tag(event: NostrEvent, name: string): string | undefined {
  return event.tags.find(([key]) => key === name)?.[1];
}

/**
 * 按 NIP-98 校验 Authorization 头，返回签名者的 pubkey。
 * 校验：kind=27235、created_at 新鲜、u 与请求 URL 完全一致、method 一致、
 * 有请求体时 payload 为请求体 sha256、签名有效。校验失败返回 null。
 */
export async function verifyNip98(request: Request, body?: ArrayBuffer): Promise<string | null> {
  const event = parseAuthHeader(request);
  if (!event || !Array.isArray(event.tags)) return null;

  if (event.kind !== AUTH_KIND) return null;

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - event.created_at) > MAX_AGE_SECONDS) return null;

  // NIP-98: u 必须与请求的绝对 URL（含查询参数）逐字符完全一致
  if (tag(event, 'u') !== request.url) return null;
  if (tag(event, 'method') !== request.method) return null;

  if (BODY_METHODS.has(request.method) && body && body.byteLength > 0) {
    // NIP-98 中 payload 标签为 SHOULD，客户端可省略，仅在提供了该标签时校验
    const payloadTag = tag(event, 'payload');
    if (payloadTag !== undefined) {
      const hash = bytesToHex(sha256(new Uint8Array(body)));
      if (payloadTag !== hash) return null;
    }
  }

  if (!verifyEvent(event)) return null;
  return event.pubkey.toLowerCase();
}
