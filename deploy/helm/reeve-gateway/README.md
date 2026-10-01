# reeve-gateway

Runs the [Claude apps gateway](https://code.claude.com/docs/en/claude-apps-gateway) on
Kubernetes. Optional, and per agent: the gateway carries Claude Code's model traffic
through your identity provider, with spend limits and managed settings per group. It sees
model traffic only - never a shell command or a file edit - which is why Reeve's guard and
policy are the product and this is a module beside them. Copilot and Cursor cannot be put
behind it at all.

The gateway itself is Anthropic's, part of the `claude` binary; this chart deploys it. It
holds a provider credential (an API key, or workload identity to Bedrock, Vertex or
Foundry) and authenticates developers through your IdP. Reeve never handles either.

## Before installing

1. **Build the image** with [`image/Dockerfile`](image/Dockerfile), around a `claude`
   binary from a pinned release that you verified. There is no published image.
2. **Register an OAuth client** in your IdP, with the gateway's
   [redirect URI](https://code.claude.com/docs/en/claude-apps-gateway-deploy#identity-provider-setup).
3. **Create a Postgres database** for it, with a role that may create tables in its schema:
   the gateway migrates at boot.
4. **Create the Secret** the configuration refers to, with `OIDC_CLIENT_ID`,
   `OIDC_CLIENT_SECRET`, `GATEWAY_JWT_SECRET` (at least 32 random bytes), `DB_PASSWORD`
   and the upstream credential, for example `ANTHROPIC_API_KEY`.

## Install

```yaml
# values.prod.yaml
image:
  repository: registry.internal/claude-gateway
  digest: sha256:...
existingSecret: claude-gateway
ingress:
  className: nginx
  host: claude-gateway.corp.example
  tlsSecretName: claude-gateway-tls
gateway:
  listen:
    public_url: https://claude-gateway.corp.example
    trusted_proxies: [10.0.0.0/8]
  oidc:
    issuer: https://keycloak.corp.example/realms/engineering
  store:
    postgres_url: postgres://claude-gateway-db.data:5432/gateway?sslmode=require
  upstreams:
    - provider: anthropic
      auth:
        api_key: ${ANTHROPIC_API_KEY}
reeveCollector:
  url: https://reeve.corp.example
```

```
helm install claude-gateway deploy/helm/reeve-gateway -f values.prod.yaml
helm test claude-gateway
```

Everything under `gateway:` is written to `gateway.yaml` as it is; the
[configuration reference](https://code.claude.com/docs/en/claude-apps-gateway-config)
documents every key, including `managed:` policies per group, `admin:` spend limits and
`access_control:`.

## What the chart refuses

Each of these would deploy and then be wrong in a way nothing reports:

| Refused | Why |
|---|---|
| A credential written into `gateway:` | It would live in the release history and the values file. Write `${VAR}` and put the value in the Secret. |
| `store.postgres_url` with a password in it | Same reason; use `store.password: ${DB_PASSWORD}`. |
| A `public_url` that is not `https://`, or differs from the Ingress host | Bearer tokens over plain HTTP; discovery metadata and IdP redirects pointing at the wrong origin. |
| No `trusted_proxies` | Every request would appear to come from the ingress controller: one rate-limit bucket for everyone, and the proxy's address in every audit event. |
| An Ingress annotation that redirects or rewrites | Claude Code does not follow redirects on the device and token endpoints; sign-in and refresh would break. |
| An image with no tag or digest, or `latest` | Every restart could run a different gateway. |
| A collector URL that is not `https://` | The gateway refuses it at boot. |
| A network policy with nobody allowed in, or nowhere allowed out | It would deny the ingress controller, or OIDC discovery and Postgres, and the gateway would never become ready. |

## What it does not do

- **Stop developers calling the provider directly.** The gateway does not enforce that it
  is the only route. Block egress to the provider except from the gateway if that matters.
- **Run Postgres.** Use the database service you already operate and back up; with spend
  limits on, losing it loses spend tracking.
- **Get tested against a live gateway here.** The chart is linted and rendered in CI, and
  every refusal above is asserted there; it has not been installed against a running
  gateway in this repository's tests, which would need a provider credential.
