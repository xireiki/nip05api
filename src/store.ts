export interface NameRecord {
  name: string;
  pubkey: string;
  relays?: string[];
  updated_at: number;
}

export interface NameStore {
  get(name: string): Promise<NameRecord | null>;
  put(record: NameRecord): Promise<void>;
  del(name: string): Promise<void>;
  list(): Promise<NameRecord[]>;
}

const KEY_PREFIX = 'name:';
const keyOf = (name: string) => `${KEY_PREFIX}${name}`;

export function createStore(kv: KVNamespace): NameStore {
  return {
    async get(name) {
      const raw = await kv.get(keyOf(name));
      return raw ? (JSON.parse(raw) as NameRecord) : null;
    },
    async put(record) {
      await kv.put(keyOf(record.name), JSON.stringify(record));
    },
    async del(name) {
      await kv.delete(keyOf(name));
    },
    // ponytail: list 先列出 key 再逐个读取；写多或量大时可改存全局索引
    async list() {
      const keys = (await kv.list({ prefix: KEY_PREFIX })).keys;
      const records = await Promise.all(keys.map((key) => kv.get(key.name)));
      return records
        .filter((raw): raw is string => raw !== null)
        .map((raw) => JSON.parse(raw) as NameRecord);
    },
  };
}
