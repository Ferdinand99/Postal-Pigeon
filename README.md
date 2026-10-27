<p align="center">
  <img src="assets/brand/pigeon-icon.png" alt="Postal Pigeon" width="160">
</p>

<h1 align="center">Postal Pigeon</h1>

<p align="center"><strong>The Hedgerow push relay. A small service that rings the doorbell on your iPhone when your own server has something to tell you, and never learns what it is.</strong></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/status-pre--release-7fb8ff.svg" alt="Status: pre-release">
</p>

> **Status: version 1 is built and not yet released.** The server works end to end against a mock Apple (see
> [`docs/api.md`](docs/api.md)). No Hedgerow app uses it yet and nobody has run it in production.

Postal Pigeon ("Pigeon") is the push-notification relay for [Hedgerow](https://hedgerow.tools/), a family of small
self-hosted apps.

## Why it exists

Apple only lets the holder of an app's push key send notifications to that app. The Hedgerow iOS apps (the Hedgerow
app for [Vigilant Vole](https://hedgerow.tools/Vigilant-Vole/), [Keen Kestrel](https://hedgerow.tools/Keen-Kestrel/)
and [Wise Wren](https://hedgerow.tools/Wise-Wren/), and later [Faithful Ferret](https://hedgerow.tools/Faithful-Ferret/))
talk to servers that **you** host, and those servers cannot hold the publisher's key. So your server asks Pigeon to
send the push, and Pigeon asks Apple.

Android does not use Pigeon. Android builds use UnifiedPush through a distributor you choose, such as ntfy.

## Who runs it

The official Pigeon is run by the Hedgerow maintainer. The official apps use it. Push is **off by default** on every
server and optional: the apps work without it and simply update when you open them or when iOS refreshes them in the
background. Because the push key belongs to the official apps, someone who builds their own app version runs their own
Pigeon with their own Apple developer account. The code is open for exactly that reason.

## Privacy in plain words

- A push says only "something changed, ask your server" or "sync now". It never says what. Notifications that show
  details are written **on your phone** after it asks your own server.
- Pigeon keeps a device address (Apple's push token for your phone), an opaque handle per connected server, and small
  counters for rate limits. It does not keep names, accounts, e-mail addresses, server addresses or content.
- Your server never sees your phone's push token, and the relay is built so that no stored record links your phone to a
  particular server.
- The operator can see your phone's push token and when pushes happen, and the internet address of your phone and of
  your server while a request is handled. A modified relay could also log which server rang which handle. These
  limits are written down in the [privacy statement](docs/design.md#14-privacy-statement).
- Apple sees the token, the time and the tiny content-free message, as it does for every iOS push.
- You can turn push off, revoke a single server from the app, or delete your device at any time.

The overview will also be on the [website](https://hedgerow.tools/Postal-Pigeon/) once it is up.

## Design

The full design is in [`docs/design.md`](docs/design.md): the API, how servers and phones register, what is stored and
for how long, rate limits and abuse controls, key handling, deployment, and a threat model covering malicious servers,
stolen credentials, a compromised relay and a leaked push key. The owner's decisions are at the end.

Shape: one small container with SQLite, one Rust binary (axum), behind a TLS reverse proxy, with a health endpoint.
It does not use the shared `vole-kit`: the relay has no sign-in, pages or translations, so it depends only on what it
needs.

## Run it

You need an Apple developer account with an APNs key (a `.p8` file, its key id and your team id), and a host name with
TLS in front of the container.

```sh
mkdir secrets
cp AuthKey_XXXXXXXXXX.p8 secrets/apns.p8
# Two random keys: one seals device tokens in the database, one signs challenges.
docker run --rm --user "$(id -u):$(id -g)" -v ./secrets:/s ghcr.io/ferdinand99/postal-pigeon keygen /s/seal.key
docker run --rm --user "$(id -u):$(id -g)" -v ./secrets:/s ghcr.io/ferdinand99/postal-pigeon keygen /s/hmac.key
sudo chown 1000:1000 secrets/*; sudo chmod 0400 secrets/*
# Edit the PP_ variables in docker-compose.yml, then:
docker compose up -d
```

[`docker-compose.yml`](docker-compose.yml) publishes the relay on `127.0.0.1:3016` only, mounts the keys read-only,
and runs the container as an unprivileged user with a read-only root filesystem and no capabilities. Point your
reverse proxy at it; it must terminate TLS (1.2 or higher), set HSTS, and add the client address to
`X-Forwarded-For`. Set `PP_TRUSTED_PROXIES` to the proxy's address as the container sees it, since the relay believes
that header from nobody else. Keep proxy access logs for at most seven days (design section 9). Images are published
for `linux/amd64` and `linux/arm64`.

Check it with `curl https://your-host/healthz` (answers `ok`) and `curl https://your-host/v1/status`.

## Configure

Everything is an environment variable with the `PP_` prefix (or the matching flag; `postal-pigeon --help` lists them).

| Variable | Meaning |
|---|---|
| `PP_APNS_KEY_PATH`, `PP_APNS_KEY_ID`, `PP_APNS_TEAM_ID` | The Apple key file, its id and the team id. All three, required. |
| `PP_APPS` | The apps served, `id=bundle.id[:alert+sync]`, comma separated: `hedgerow=com.example.hedgerow,ferret=com.example.ferret:sync`. The bundle id is the APNs topic. Required. |
| `PP_APNS_ENVIRONMENT` | `production`, `sandbox` or both (the default). Devices say which they use; tokens only work in the environment that issued them. |
| `PP_SEAL_KEY_FILE`, `PP_HMAC_KEY_FILE` | Key files (64 hex characters; make them with `postal-pigeon keygen`). Required. Keep them off the data volume. |
| `PP_SEAL_OLD_KEY_FILES` | Older seal keys, comma separated, kept while tokens are re-sealed under the current one (rotation below). |
| `PP_BIND` | Listen address; default `127.0.0.1:3010` (the image uses `0.0.0.0:3010`). |
| `PP_DATA_DIR` | Folder for the database (`pigeon.sqlite`); default `data` (`/data` in the image). |
| `PP_PUBLIC_URL` | The public address, for logs. |
| `PP_TRUSTED_PROXIES` | Addresses or networks whose `X-Forwarded-For` is believed. |
| `PP_LIMITS_FILE` | JSON file overriding any limit ([`docs/api.md`](docs/api.md#limits)). |
| `RUST_LOG` | Log level; default `info`. |

The relay logs start-up, errors with short codes and aggregate counters. It never logs tokens, handles, credentials,
`ref` values, event ids or client addresses.

## Operate it

Admin is on the command line, inside the container (there is no admin web page):

```sh
docker compose exec postal-pigeon postal-pigeon admin stats
docker compose exec postal-pigeon postal-pigeon admin instances
docker compose exec postal-pigeon postal-pigeon admin block-instance <id>
docker compose exec postal-pigeon postal-pigeon admin unblock-instance <id>
docker compose exec postal-pigeon postal-pigeon admin set-tier <id> established
docker compose exec postal-pigeon postal-pigeon admin delete-instance <id>
docker compose exec postal-pigeon postal-pigeon admin delete-device <hrd_...>
docker compose exec postal-pigeon postal-pigeon admin send-test --device <hrh_... or hrd_...>
```

`send-test` pushes a test alert (or `--kind sync`) to a registered device, ignoring rate limits, and says what Apple
answered. Use it after changing the APNs key.

- **Rotating the APNs key:** create a second key at Apple, change `PP_APNS_KEY_PATH` and `PP_APNS_KEY_ID`, restart,
  run `send-test` to your own device, then revoke the old key. No user is affected.
- **Rotating the seal key:** make a new key file, set it as `PP_SEAL_KEY_FILE` and the old one in
  `PP_SEAL_OLD_KEY_FILES`, restart. Tokens are re-sealed at start-up and then hourly (`admin reseal` does it at once).
  Remove the old key when `admin reseal` says `re-sealed 0 tokens`.
- **Backups** are not needed: if the database is lost, apps and servers register again by themselves. If you keep
  snapshots, encrypt them and delete them after seven days.
- **Maintenance** (retention, tiers, re-sealing) runs at start-up and hourly; `admin maintain` runs it now.

## API overview

The API is `/v1` JSON over HTTPS; the reference for app and server developers is [`docs/api.md`](docs/api.md).

| Who | Call |
|---|---|
| Server | `GET /v1/challenge`, `POST /v1/instances` (proof of work), `POST /v1/instances/self/rotate`, `DELETE /v1/instances/self` |
| App | `POST /v1/devices`, `PUT` and `DELETE /v1/devices/{id}`, `POST`, `GET` and `DELETE` on `/v1/devices/{id}/handles` |
| Server | `POST /v1/push` with a handle |
| Anyone | `GET /healthz`, `GET /v1/status` |

## Develop

The tests start the relay in-process and a mock Apple server over cleartext HTTP/2; nothing ever calls Apple.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

## Contributing

Pigeon is not open for contributions yet. When it is, a contributor licence agreement will be required for code
contributions. Until then, issues and ideas are welcome on the [issue tracker](https://github.com/Ferdinand99/Postal-Pigeon/issues).
Please report security problems privately, as described in [`SECURITY.md`](SECURITY.md).

Postal Pigeon is part of [Hedgerow](https://hedgerow.tools/), with [Vigilant Vole](https://hedgerow.tools/Vigilant-Vole/),
[Nimble Newt](https://hedgerow.tools/Nimble-Newt/), [Keen Kestrel](https://hedgerow.tools/Keen-Kestrel/),
[Wise Wren](https://hedgerow.tools/Wise-Wren/) and [Faithful Ferret](https://hedgerow.tools/Faithful-Ferret/).

## License

[GNU AGPL-3.0-only](LICENSE)
