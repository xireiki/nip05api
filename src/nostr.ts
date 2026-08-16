import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

export interface NostrEvent {
  id?: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig?: string;
}

/** NIP-01 事件 ID：对规范化序列化做 sha256。签名/验签都基于此值。 */
export function eventId(event: NostrEvent): string {
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  return bytesToHex(sha256(serialized));
}

/** 校验事件签名（BIP-340 schnorr）。pubkey 与 pubkey 均为小写 hex。 */
export function verifyEvent(event: NostrEvent): boolean {
  if (
    !event.sig ||
    !/^[0-9a-f]{64}$/i.test(event.pubkey) ||
    !/^[0-9a-f]{128}$/i.test(event.sig)
  ) {
    return false;
  }
  try {
    return schnorr.verify(event.sig, eventId(event), event.pubkey);
  } catch {
    return false;
  }
}
