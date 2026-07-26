# SulaShop OmniRoute deployment

## Source baseline

- Upstream: `https://github.com/diegosouzapw/OmniRoute`
- Baseline branch: `release/v3.8.49`
- Baseline commit: `1f04333a19139669115bf049ca96f2136b31524a`
- Fork: `https://github.com/quocviet8x/OmniRoute`

## Custom channels

- `auto/bestfree`: usable free candidates first; paid candidates only after free candidates fail.
- `auto/bestcodex`: all active Codex candidates first in model-major priority; non-Codex paid candidates second; free candidates last.

The upstream `auto/best-free` channel is preserved unchanged. The custom names deliberately omit the hyphen to avoid collisions with upstream channels.

## Build

Use Node 22 and build one coherent frontend/backend artifact:

```bash
npm ci
npm run typecheck:core
node --import tsx/esm --test tests/unit/services/sulashop-auto-policy-contract.test.mjs
npm run build:release
npm run build:cli
```

Required artifact checks:

```bash
test -f dist/server.js
test -f dist/.build/next/BUILD_ID
test -d dist/.build/next/static
test -f dist/.build/next/server/app/login/page.js
node --check dist/server.js
```

Never deploy a backend-only `.build/next` tree over production. The frontend static chunks and server pages must come from the same build.

## Production

- Runtime: `/root/.local/lib/node_modules/omniroute/dist`
- Data: `/root/.omniroute`
- Service: `omniroute.service`
- Local endpoint: `http://127.0.0.1:20129`
- Public endpoint: `https://omniroute.sulashop.com`

Back up runtime and data before deployment. Deploy the full `dist/` atomically, restart the service, and verify:

```bash
systemctl is-active omniroute.service
curl -f http://127.0.0.1:20129/v1/models
curl -fL https://omniroute.sulashop.com/login
```

Release gates:

1. Login page renders without JavaScript errors.
2. `/v1/models` lists `auto/bestfree` and `auto/bestcodex`.
3. `auto/bestfree` attempts a free target first.
4. `auto/bestcodex` logs both Codex selection and Codex as execution target 1.
5. Existing upstream channels still appear.

Rollback by restoring the complete backed-up runtime directory and restarting `omniroute.service`.
