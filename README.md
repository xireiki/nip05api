# nip05api

基于 Cloudflare Worker 的 [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md) 认证服务器。数据保存在 Cloudflare KV，增删改接口使用 [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) HTTP 认证，仅允许管理员公钥操作。

## 功能

- `GET /.well-known/nostr.json?name=<name>`：对外公开的 NIP-05 查询接口（带 CORS 与缓存头，支持可选 `relays`）
- `GET /.well-known/nostr.json`（不带 `name`）：管理员列出全部记录（需 NIP-98 + 管理员）
- `POST /.well-known/nostr.json`：新增 name（需 NIP-98 + 管理员），body 为 `{"name","pubkey","relays?"}`；已存在返回 409
- `PATCH /.well-known/nostr.json`：修改 name（需 NIP-98 + 管理员），body 为 `{"name","pubkey?","relays?"}`，只更新提供的字段；不存在返回 404
- `DELETE /.well-known/nostr.json?name=<name>`：删除 name（需 NIP-98 + 管理员）

管理员公钥清单 `ADMIN_PUBKEYS` 只用于鉴权比对，永不对外暴露。

## 目录结构

```
src/
  index.ts    Worker 入口：路由、鉴权、错误处理
  nostr.ts    事件序列化（NIP-01）与 schnorr 验签
  nip98.ts    NIP-98 认证校验，返回签名者 pubkey
  store.ts    KV 存储抽象，统一 key 规则
scripts/
  auth.mjs    生成 NIP-98 Authorization 头，方便 curl 测试
test/
  nip98.test.ts  验签与认证逻辑测试（含参考实现向量）
wrangler.toml    部署配置
```

## 部署

前置：Node.js 18+、已登录 wrangler（`npx wrangler login`）。

```bash
npm install
npx wrangler kv namespace create nip05kv     # 创建 KV，拿到 namespace id
```

把返回的 id 填入 `wrangler.toml` 的 `id` 字段，并把你的 nostr 公钥（hex）填入 `ADMIN_PUBKEYS`（多个公钥用逗号分隔）：

```toml
[[kv_namespaces]]
binding = "nip05kv"
id = "<你的-kv-id>"

[vars]
ADMIN_PUBKEYS = "<你的-hex-公钥>"
```

```bash
npm run deploy     # 或 npx wrangler deploy
```

本地开发：`npm run dev`（wrangler 会本地模拟 KV）。

## 使用

### 查询

```bash
curl 'https://<你的域名>/.well-known/nostr.json?name=alice'
# {"names":{"alice":"79be..."},"relays":{"79be...":["wss://relay1"]}}
```

### 增删改（NIP-98）

用 `scripts/auth.mjs` 生成请求头。它需要操作者的私钥，仅用于测试或自用脚本，切勿泄露。

```bash
WK=https://<你的域名>/.well-known/nostr.json

# 新增
BODY='{"name":"alice","pubkey":"79be...","relays":["wss://relay1"]}'
AUTH=$(node scripts/auth.mjs <你的私钥hex> POST $WK "$BODY")
curl -X POST -H "Authorization: $AUTH" -H 'content-type: application/json' -d "$BODY" $WK

# 修改（只更新提供的字段）
BODY='{"name":"alice","relays":["wss://relay2"]}'
AUTH=$(node scripts/auth.mjs <你的私钥hex> PATCH $WK "$BODY")
curl -X PATCH -H "Authorization: $AUTH" -H 'content-type: application/json' -d "$BODY" $WK

# 删除（name 通过查询参数）
AUTH=$(node scripts/auth.mjs <你的私钥hex> DELETE "$WK?name=alice")
curl -X DELETE -H "Authorization: $AUTH" "$WK?name=alice"

# 管理员列出全部记录（不带 name 参数）
AUTH=$(node scripts/auth.mjs <你的私钥hex> GET $WK)
curl -H "Authorization: $AUTH" $WK
```

注意：签名时用的 URL 必须与请求 URL 完全一致（NIP-98 的 `u` 标签逐字符比对，DELETE 要带上 `?name=...`），且事件创建时间须在 60 秒内。

## 测试

```bash
npm test          # vitest：验签、序列化、NIP-98 各校验分支
npm run typecheck # tsc 严格模式
```

测试中的参考向量由 nostr-tools 生成，用于确认事件序列化与生态实现一致（NIP-98 官方文档中的示例事件本身签名无法验证，勿直接用作向量）。

## 注意事项

- Cloudflare KV 是最终一致存储，写入后读取可能短时滞后
- NIP-05 接口返回 `cache-control: public, max-age=300`，更新后客户端最长 5 分钟生效
- `ADMIN_PUBKEYS` 留空时所有增删改请求都会被拒绝（安全失败）
