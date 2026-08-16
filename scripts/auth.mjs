// 生成 NIP-98 Authorization 头，方便用 curl 测试增删改接口
// 用法: node scripts/auth.mjs <privkey-hex> <METHOD> <url> [body-json]
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const [priv, method, url, body] = process.argv.slice(2);
if (!priv || !method || !url) {
  console.error('usage: node scripts/auth.mjs <privkey-hex> <METHOD> <url> [body-json]');
  process.exit(1);
}

const event = {
  pubkey: bytesToHex(schnorr.getPublicKey(priv)),
  created_at: Math.floor(Date.now() / 1000),
  kind: 27235,
  tags: [
    ['u', url],
    ['method', method],
  ],
  content: '',
};
if (body) event.tags.push(['payload', bytesToHex(sha256(new TextEncoder().encode(body)))]);

const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
event.sig = bytesToHex(schnorr.sign(bytesToHex(sha256(serialized)), priv));

console.log('Nostr ' + Buffer.from(JSON.stringify(event)).toString('base64'));
