# Autentico Helm chart

Deploys [Autentico](https://github.com/eugenioenko/autentico), a self-contained
OAuth 2.0 / OpenID Connect identity provider.

## Storage model

Autentico stores all state in one SQLite database (`AUTENTICO_DB_FILE_PATH`,
default `./autentico.db`). The container working directory is `/app/data`, so
the chart mounts a persistent volume there and sets the database path to
`/app/data/autentico.db`.

When `application.launchWithAutoSetup` is enabled, the chart also passes
`--env-file <persistence.mountPath>/.env`, so the generated `.env` is written to
the same volume as the database even if `persistence.mountPath` is overridden.

SQLite is a single-writer database. The chart therefore:

- runs exactly one replica;
- requests a `ReadWriteOnce` volume;
- uses the `Recreate` deployment strategy, so the old pod releases the volume
  before the replacement starts.

Do not enable horizontal autoscaling or run multiple releases against the same
database file.

By default the chart creates a `PersistentVolumeClaim` and lets the cluster's
default `StorageClass` provision a `PersistentVolume`. A static `hostPath` PV is
available for clusters without a dynamic provisioner.

## Install

```bash
helm install autentico ./deploy/helm/autentico \
  --namespace autentico \
  --create-namespace \
  --set application.appUrl=https://auth.example.com
```

Then open `https://auth.example.com/onboard` to create the first administrator.

With the default `application.launchWithAutoSetup: true`, the first start
generates `.env` with the signing keys and other secrets on the data volume.
That is convenient for a test installation. For production, supply the
settings from a Kubernetes Secret instead.

## Production secrets

Generate the values with the Autentico binary (`autentico init`) or your secret
manager. The required bootstrap variables are:

- `AUTENTICO_ACCESS_TOKEN_SECRET`
- `AUTENTICO_REFRESH_TOKEN_SECRET`
- `AUTENTICO_CSRF_SECRET_KEY`
- `AUTENTICO_PRIVATE_KEY`
- `AUTENTICO_TOTP_ENCRYPTION_KEY`

Create a Secret and reference it:

```bash
kubectl create secret generic autentico-secrets \
  --namespace autentico \
  --from-literal=AUTENTICO_ACCESS_TOKEN_SECRET='...' \
  --from-literal=AUTENTICO_REFRESH_TOKEN_SECRET='...' \
  --from-literal=AUTENTICO_CSRF_SECRET_KEY='...' \
  --from-literal=AUTENTICO_PRIVATE_KEY='...' \
  --from-literal=AUTENTICO_TOTP_ENCRYPTION_KEY='...'
```

```yaml
application:
  launchWithAutoSetup: false
  appUrl: https://auth.example.com

envFrom:
  - secretRef:
      name: autentico-secrets
```

Keep `AUTENTICO_TOTP_ENCRYPTION_KEY` together with database backups. Without
it, encrypted TOTP enrollments cannot be restored.

## Persistence options

Use the chart-managed PVC (default):

```yaml
persistence:
  enabled: true
  size: 10Gi
  storageClass: "" # cluster default
```

Use an existing PVC:

```yaml
persistence:
  enabled: true
  existingClaim: autentico-data
```

Create a static `hostPath` PV for a single-node/local cluster:

```yaml
persistence:
  enabled: true
  createPV: true
  storageClass: manual
  pv:
    hostPath: /var/lib/autentico
    nodeAffinity:
      required:
        nodeSelectorTerms:
          - matchExpressions:
              - key: kubernetes.io/hostname
                operator: In
                values:
                  - node-1
```

On clusters with dynamic provisioning, leave `createPV: false`.

To keep the database when running `helm uninstall`:

```yaml
persistence:
  annotations:
    helm.sh/resource-policy: keep
```

## OIDC issuer under a subpath

`application.oauthPath` is optional. When it is empty, Autentico uses its
built-in default `/oauth2`. When set, the OIDC issuer is
`application.appUrl + application.oauthPath`, so the issuer can live under a
path prefix without a reverse-proxy rewrite:

```yaml
application:
  appUrl: https://auth.example.com
  oauthPath: /monitoring/auth
```

This produces:

- issuer: `https://auth.example.com/monitoring/auth`
- discovery: `https://auth.example.com/monitoring/auth/.well-known/openid-configuration`
- authorize: `https://auth.example.com/monitoring/auth/authorize`

The admin and account UIs remain at `/admin` and `/account`. Keep `appUrl` as an
origin without a path; a path in `appUrl` breaks WebAuthn origins for passkeys.
Use an Ingress/Gateway path such as `/monitoring/auth` without rewriting it,
because the application registers the OAuth routes at that path itself.

Running the entire application (including `/admin` and `/account`) under one
prefix is not supported without proxy rewriting and custom UI base paths.

## Probes

The chart uses `GET /healthz` for startup, readiness and liveness probes. The
startup probe allows up to five minutes for database migrations on large
databases.

## Upgrades and migrations

Routine schema migrations run automatically on startup. Major migrations are
refused by `start` and must be approved with `autentico migrate`. Before a major
upgrade:

1. Back up the data volume.
2. Scale the deployment to zero.
3. Run `autentico migrate --approve-major=<versions>` in a one-off pod that
   mounts the same PVC and uses the same secrets.
4. Scale the deployment back to one.

The chart does not run migrations as a Helm hook because a failed or interactive
migration must be handled explicitly.

## Backups

Back up the SQLite database with a consistent snapshot. The Autentico image
does not ship the `sqlite3` CLI, so run a one-off Pod or Job that mounts the PVC
and uses an image containing `sqlite3`:

```bash
sqlite3 /app/data/autentico.db ".backup '/backup/autentico-$(date +%Y%m%d-%H%M%S).db'"
```

Store backups outside the volume and keep `AUTENTICO_TOTP_ENCRYPTION_KEY` with
them. If the volume's access mode does not allow a second pod on the same node,
stop the deployment first.

## Important values

| Key | Default | Description |
| --- | --- | --- |
| `image.registry` | `ghcr.io` | Image registry |
| `image.repository` | `eugenioenko/autentico` | Image repository |
| `image.tag` | `latest` | Pin a release tag in production |
| `application.appUrl` | `""` | Public base URL (origin); set this in Kubernetes |
| `application.oauthPath` | `""` | Optional OAuth2/OIDC path prefix; empty uses `/oauth2`; issuer = `appUrl + oauthPath` |
| `application.launchWithAutoSetup` | `true` | Generate `.env` on first start |
| `application.extraArgs` | `[]` | Extra arguments after `start` |
| `persistence.enabled` | `true` | Mount persistent storage |
| `persistence.size` | `5Gi` | PVC size |
| `persistence.existingClaim` | `""` | Use an existing PVC |
| `persistence.createPV` | `false` | Create a static `hostPath` PV |
| `service.port` | `9999` | Service and container port |
| `ingress.enabled` | `false` | Create an Ingress |
| `httpRoute.enabled` | `false` | Create a Gateway API HTTPRoute |
| `resources` | `{}` | Set requests/limits for production |
| `tests.enabled` | `true` | Render the `helm test` pod |

`AUTENTICO_LISTEN_PORT` is set by the chart to `service.port`. Do not override it
through `env`; it must match the container port.

## Security notes

- The ServiceAccount token is not mounted; Autentico does not call the
  Kubernetes API.
- The container drops all Linux capabilities and enables the `RuntimeDefault`
  seccomp profile.
- The published image currently runs as root. If you harden it with
  `runAsNonRoot`, also set `podSecurityContext.fsGroup` so the data volume is
  writable by that user.
- Put Autentico behind TLS (Ingress/Gateway or a service mesh) and set
  `application.appUrl` to the public `https://` URL. The issuer must exactly
  match the URL clients use.

## First-run URL caveat

The first start persists `.env` (including `AUTENTICO_APP_URL`) on the data
volume in the auto-setup mode. Changing `application.appUrl` later does not
rewrite the existing `.env` and can leave the built-in admin client with stale
callback URLs. For a fresh test installation, delete the PVC and reinstall; in
production, plan the public URL before the first start.
