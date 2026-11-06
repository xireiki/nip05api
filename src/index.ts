import { verifyNip98 } from './nip98';
import { createStore, type NameRecord } from './store';

export interface Env {
  nip05kv: KVNamespace;
  ADMIN_PUBKEYS: string;
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
};

const NIP05_CACHE_MAX_AGE = 300;

function json(data: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...CORS_HEADERS, ...extra },
  });
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const badRequest = (message: string) => new HttpError(400, message);

/** 校验 NIP-98 并把 pubkey 与管理员白名单比对，失败抛错。 */
async function authenticate(request: Request, env: Env, body?: ArrayBuffer): Promise<string> {
  const pubkey = await verifyNip98(request, body);
  if (!pubkey) throw new HttpError(401, 'invalid NIP-98 authorization');
  const admins = env.ADMIN_PUBKEYS.split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (!admins.includes(pubkey)) throw new HttpError(403, 'pubkey is not an admin');
  return pubkey;
}

function toNip05(record: NameRecord): Record<string, unknown> {
  const out: Record<string, unknown> = { names: { [record.name]: record.pubkey } };
  if (record.relays?.length) out.relays = { [record.pubkey]: record.relays };
  return out;
}

const cacheHeader = { 'cache-control': `public, max-age=${NIP05_CACHE_MAX_AGE}` };

async function handleNip05Lookup(request: Request, env: Env): Promise<Response> {
  const requested = new URL(request.url).searchParams.get('name') ?? '';
  const store = createStore(env.nip05kv);
  const record = await store.get(requested.toLowerCase());
  if (!record) return json({ error: `name "${requested}" not found` }, 404, cacheHeader);
  // 客户端按自己请求的 local-part 精确匹配 names 键，因此回显请求中的写法
  return json(toNip05({ ...record, name: requested }), 200, cacheHeader);
}

async function handleAdmin(request: Request, env: Env): Promise<Response> {
  const store = createStore(env.nip05kv);

  if (request.method === 'GET') {
    await authenticate(request, env);
    const names = await store.list();
    return json({ names });
  }

  if (request.method === 'POST') {
    const body = await request.arrayBuffer();
    await authenticate(request, env, body);
    const parsed = parseRecord(body);
    if (!parsed.pubkey) throw badRequest('pubkey is required');
    const record: NameRecord = {
      name: parsed.name,
      pubkey: parsed.pubkey,
      relays: parsed.relays ?? [],
      updated_at: Math.floor(Date.now() / 1000),
    };
    if (await store.get(record.name)) throw new HttpError(409, `name "${record.name}" already exists`);
    await store.put(record);
    return json({ ok: true, name: record.name });
  }

  if (request.method === 'PATCH') {
    const body = await request.arrayBuffer();
    await authenticate(request, env, body);
    const parsed = parseRecord(body);
    const existing = await store.get(parsed.name);
    if (!existing) throw new HttpError(404, `name "${parsed.name}" not found`);
    const merged: NameRecord = {
      ...existing,
      pubkey: parsed.pubkey ?? existing.pubkey,
      relays: parsed.relays ?? existing.relays,
      updated_at: Math.floor(Date.now() / 1000),
    };
    await store.put(merged);
    return json({ ok: true, name: parsed.name });
  }

  if (request.method === 'DELETE') {
    const name = new URL(request.url).searchParams.get('name')?.toLowerCase();
    if (!name) throw badRequest('missing "name" query parameter');
    await authenticate(request, env);
    await store.del(name);
    return json({ ok: true, name });
  }

  throw new HttpError(405, 'method not allowed');
}

function parseRecord(body: ArrayBuffer): { name: string; pubkey?: string; relays?: string[] } {
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
  } catch {
    throw badRequest('invalid JSON body');
  }
  const rawName = data.name;
  if (typeof rawName !== 'string' || !/^[a-z0-9-_.]{1,64}$/i.test(rawName)) {
    throw badRequest('name must be 1-64 chars of a-z0-9-_.');
  }
  const name = rawName.toLowerCase();
  let pubkey: string | undefined;
  if (data.pubkey !== undefined) {
    if (typeof data.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(data.pubkey)) {
      throw badRequest('pubkey must be a 64-char hex string');
    }
    pubkey = data.pubkey.toLowerCase();
  }
  let relays: string[] | undefined;
  if (data.relays !== undefined) {
    if (!Array.isArray(data.relays)) throw badRequest('relays must be an array of strings');
    relays = data.relays.filter((r): r is string => typeof r === 'string');
  }
  return { name, pubkey, relays };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      if (url.pathname === '/.well-known/nostr.json') {
        // GET 带 name 走公开 NIP-05 查询；其余（无 name 的列表与增删改）走管理员接口
        return request.method === 'GET' && url.searchParams.has('name')
          ? await handleNip05Lookup(request, env)
          : await handleAdmin(request, env);
      }
      throw new HttpError(404, 'not found');
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      console.error(err);
      return json({ error: 'internal server error' }, 500);
    }
  },
};
