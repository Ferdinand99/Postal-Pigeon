# Security review, October 2026

Date: 29 October 2026. Covers Postal Pigeon up to `43c3041` (the 0.1.1 release plus the rusqlite 0.41 bump). The
client side in vole-kit 0.7.0 (`kit/src/push`) was read for compatibility only. An earlier internal review of the first
version (its notes are in "Hardening after the October 2026 review" in [`design.md`](design.md)) is not repeated here.

## Method and limits

This was a read-only code review of the whole relay, followed by a failing test for every finding rated Medium or
higher, and a fix with tests. It was not an external audit and it was not done by a professional security firm. Each
candidate was traced to the lines that cause it, tried against the code that is meant to stop it, and rated. The tests
ran in-process against a mock Apple server; nothing was sent to a live relay or to Apple, and nothing was fuzzed or
load-tested. Figures for memory and CPU in the findings are estimates from reading the code, not measurements.

The formatting check, clippy with warnings denied, the tests and `cargo deny check advisories` were run in a container
on a separate test host.

Treat this as one careful review, not as a guarantee.

## Scope

All of `src/` (the API handlers, registration and proof of work, credentials and sealing, limiters, the database and
retention, the APNs client, the strike breaker, configuration, the listener and the admin commands), the tests, the
Dockerfile and `docker-compose.yml`, and `docs/api.md` and `docs/design.md` for claims the code has to meet. Checked
specifically: registration and the proof of work (difficulty, replay, scale), device and instance secrets (generation,
hashing, comparison), authorisation on every route, handle unlinkability, rate limits and quotas, payload validation,
handling of the APNs key, logging, SQLite growth, the HTTP surface, `X-Forwarded-For` trust, the container, and
dependency advisories.

The attackers considered: an anonymous internet client; a registered instance (a self-hosted server, treated as
hostile) holding the handles its users gave it; a web page that makes a visitor's browser send requests; and a holder of
a leaked handle or instance credential.

Held up in review: secrets are 256-bit random, only their SHA-256 is stored, and they are compared with the
constant-time comparison from `aws-lc-rs`; every device, handle and revoke query is scoped to the device whose manage
key was presented, and an instance has no route that reads or lists anything; unknown and revoked handles answer the
same, and the unknown-handle allowance stops guessing; device tokens are sealed with AES-256-GCM bound to the device id,
never appear in a response, and are never logged; the `.p8` is read once, wiped from memory, and appears in no log line,
`Debug` output or answer; the push body is built from validated fields only (`ref` and `collapse` are restricted to a
small alphabet, `tag` must be 16 bytes of base64url) and `collapse` reaches Apple only as a keyed hash; the challenge's
difficulty is inside its MAC, challenges are single-use, and address limits are checked before a challenge is
remembered; every SQL statement is parameterised; `X-Forwarded-For` is read from the right and only through trusted
proxies; the container runs as uid 1000 with a read-only root, no capabilities, loopback-only publishing, and the
secrets as 0400 files rather than environment variables.

## Findings

All three Medium findings are fixed, with tests, on the branch `fix/security-review`.

| ID | Severity | Title | Status |
|---|---|---|---|
| PIG-01 | Medium | Any web page could post to the relay from its visitors' addresses | Fixed |
| PIG-02 | Medium | Junk registrations could lock new devices out for up to 90 days | Fixed |
| PIG-03 | Medium | No per-address cap on requests in progress; a few slow clients could shed everyone | Fixed |
| PIG-04 | Low | Each connection could buffer about 400 KiB of request head | Fixed |
| PIG-05 | Low | The shared provider-token folder sat at a predictable path in the shared temp directory | Fixed |
| PIG-06 | Low | The compose `/tmp` tmpfs had no size cap or `noexec` | Fixed |
| PIG-07 | Low | `405` and bad-path answers were not in the API's error format | Fixed |
| PIG-08 | Low | Anyone can raise the proof-of-work difficulty for everybody | Accepted |
| PIG-09 | Low | The `instances` table has no row cap | Open |
| PIG-10 | Low | Servers can learn that two handles share a device; dates in the database link handles to instances | Accepted |
| PIG-11 | Low | Used challenges and handled events are forgotten on restart | Accepted |
| PIG-12 | Low | Registration and retention work holds the single database lock | Open |
| PIG-13 | Info | Client addresses rest on the proxy appending to `X-Forwarded-For` | Documented |
| PIG-14 | Info | Smaller observations | Accepted |
| Advisories | n/a | `cargo deny check advisories` | Clean (see below) |

Counts: Critical 0, High 0, Medium 3 found and 3 fixed, Low 9 found and 4 fixed, Info 2.

### PIG-01, Medium: any web page could post to the relay from its visitors' addresses

`ApiJson` read the body of every JSON route without looking at `Content-Type`. A browser may send a cross-site `POST`
with `text/plain`, a form encoding or no type at all without asking the server first (no CORS preflight), and
`POST /v1/devices` needs no credentials. So a page, an ad or an injected script could register devices from each
visitor's address: it spends the visitor's registration budget (20 an hour and 100 a day for the address, 100 and 500
for the network) instead of its own, can lock a visitor, or a whole mobile network, out of registering their own
device, and creates junk rows from as many addresses as it has visitors. That bypasses the address limits that PIG-02
depends on. A test sends the four content types a page can use to `/v1/devices`, `/v1/instances` and `/v1/push`, and
the pre-fix code accepted them and created the device.

Fix: a body must be `Content-Type: application/json` (a charset is fine) or the answer is `415 unsupported_media_type`.
`application/json` is not one a page may send without a preflight, and the relay answers no CORS headers (a test
covers an `OPTIONS` preflight). vole-kit sends JSON with reqwest's `json()`, so servers are unaffected; the Hedgerow app
must set the header, which `docs/api.md` already asked for.

### PIG-02, Medium: junk registrations could lock new devices out for up to 90 days

Device registration is open, rows only leave after 90 days without a keep-alive, and past `max_devices` (1,000,000) a
new token was refused with `503` for everyone. The address and network limits slow a filler down, but a botnet, or
PIG-01, fills a million rows in a few days, and nobody new could register for the time it takes them to expire. Junk
rows are never struck or deleted, since no handle is ever given to a server and so nothing is ever sent to them.

Fix: when the table is full, registration deletes the oldest records that have no handle, never had a push accepted and
are over an hour old (1% of the cap at a time), and refuses only if there are none. A real app that loses a record this
way finds `404` on its next keep-alive and registers again, which `docs/api.md` already describes. Records with a
handle, records Apple has accepted a push for, and records younger than an hour are never evicted. Tests cover a full
table with and without devices in use.

Still true: a large botnet can keep registering junk and push out genuinely idle new devices (those that have no handle
yet after an hour). Their app registers again. The cap itself is unchanged.

### PIG-03, Medium: no per-address cap on requests in progress

A request holds one of 2048 permits from the moment it arrives until its body has been read and answered, and the body
may take 10 seconds. A client that opens connections and trickles bodies (a few bytes of a 2 KiB JSON, then nothing)
keeps a permit for 10 seconds per connection, so about 2048 slow connections, which one small machine can open through
a proxy that passes the body on as it arrives (the usual default), made every other route answer `503` for as long as it kept
going. This needs no credentials and very little bandwidth. The health check has its own pool and kept answering, which
hid the problem from a health probe.

Fix: one client address (an IPv6 /64, and behind the proxy the real client) may have 64 requests running; the next one
gets `429 rate_limited` with `Retry-After: 1`. The cap is released when the request ends or the client hangs up, the
health routes are not counted, and the number is `max_inflight_per_addr` in the limits file. A test holds two bodies
open and checks that the address is refused, another address and the health check are not, and hanging up frees the
slots; another checks the cap follows `X-Forwarded-For` behind a trusted proxy.

Still true: an attacker with many addresses can still hold many permits (2048 divided by 64 is 32 addresses). That is
the case for the proxy's own per-address connection and rate limits, which the design already asks for.

### Low findings that are fixed

- **PIG-04, request head size.** hyper buffers up to about 400 KiB of request line and headers per connection by
  default. At the 4096-connection cap that is more than the container's 256 MiB, so connections sending large heads
  directly to the relay (the proxy normally absorbs this) could get it killed. The buffer is now 16 KiB and a larger
  head gets `431`. A test sends 64 KiB.
- **PIG-05, token folder.** Without a container the shared provider token goes in `<temp dir>/postal-pigeon`. Someone
  else on the machine could create that folder first, read the token (valid for an hour) or plant one. The folder must
  now be a real directory (not a link) that the relay can set to 0700, else it is not used and each process makes its
  own token. In the container (a private tmpfs) nothing changes.
- **PIG-06, compose tmpfs.** `/tmp` is now `size=16m,noexec,nosuid,nodev`. Only the provider token lives there.
- **PIG-07, error format.** `405` and a path parameter that cannot be decoded were answered by the framework with an
  empty or plain-text body. They are now JSON like every other error.

### Accepted and open items

- **PIG-08, proof-of-work difficulty is a lever (accepted).** The adaptive difficulty rises with the last hour's
  registrations and 4 more bits above 5000 a day, up to 32 bits, for everybody. At 20 bits a registration is about a
  second for a server and about a millisecond on a GPU, so the proof of work does not stop anyone with hardware; the address and
  network limits do. Someone with a few hundred networks (IPv6 prefixes included) can register 5000 instances in a day, push
  the difficulty to 32 bits, and make registration for real servers take many minutes (vole-kit gives up at 240 seconds
  and retries, so it works slowly rather than not at all). Existing credentials, sending and the apps are not affected.
  Lowering `pow_high_water_extra_bits` trades this against cheaper spam. The design already lists it ("a large botnet can
  still slow registration down").
- **PIG-09, no row cap on `instances` (open).** Registered instances that are never used still live 180 days, and one
  authenticated call every few months keeps one alive. At 25 registrations a day per network, filling the disk takes an
  attacker with tens of thousands of networks, so this is rated Low. Each row is about 150 bytes. A row cap or a shorter
  life for instances that never sent a push are options; neither is built because either also hands the attacker a way to
  refuse real registrations. `admin stats` shows the count, and the log warns above 5000 registrations in a day.
- **PIG-10, unlinkability (accepted).** The relay knows which handles belong to one device and, while it handles a
  push, which instance sent it; the design says so. Beyond that: (a) the per-device send limit, the unverified-device
  limit and Apple's `429` backoff are per device, so a server can see `limited` on its own handle because of pushes
  another server's handle made to the same device. Reaching the device limit needs five or more cooperating servers for
  alerts, so a single device cannot be linked this way in practice, but the answer is a side channel. (b) `last_used`
  dates on handles and instances, and the daily usage rows, are stored as days; with few active servers, someone who
  has a copy of the database could line the days up. Neither gives a server a device token or another server's handle.
- **PIG-11, memory is lost on restart (accepted).** The used-challenge set (5 minutes) and the handled-event set (15
  minutes) are in memory, as designed. For a few minutes after a restart a solved challenge can be used again (the
  address limits still apply) and a retried push is sent twice.
- **PIG-12, one database lock (open).** All database work goes through one connection behind a mutex. Every new device
  counts the table (`COUNT(*)`, a scan of an index) while holding it, and the hourly retention pass deletes expired rows
  with `secure_delete` on, so a very large batch of junk expiring together can stall requests, and the health check,
  for as long as the delete takes. The numbers are estimates and were not measured. A cached device count and deleting
  expired rows in batches are the obvious next steps.
- **PIG-13, `X-Forwarded-For` (documented).** The relay takes the right-most entry that is not a trusted proxy. That is
  only the client if the proxy appends the address it saw (Traefik, which Pangolin uses, does by default) and the relay's port
  is reachable only through it. The compose file publishes on loopback and trusts one `/32`. The proxy's settings on the
  production host were not reviewed.
- **PIG-14, observations (accepted).** `/v1/status` shows the version and whether registration is busy, on purpose.
  `admin send-test` takes a handle as a command-line argument, which shell history and `ps` can see; it is run by the
  administrator inside the container. Base images are pinned by tag, not digest. A new instance moves to the
  "established" tier after seven days without a limit hit, even if it has never sent anything; the per-handle and
  per-device limits are what protect people, not the tier. The relay is Unix-only in practice (key file modes).

### Dependencies

`cargo deny check advisories` is configured (`deny.toml`, run weekly by the Audit workflow). It was run on 29 October 2026 (cargo-deny 0.20.2, advisory database of that day, `Cargo.lock` at `43c3041`) and found no advisories, with no ignores in `deny.toml`.

## Not covered

- The Hedgerow iOS app and its Notification Service Extension, and the vole-kit client beyond reading it for
  compatibility.
- The production host: the Pangolin/Traefik configuration, TLS versions and HSTS, the firewall, access-log retention,
  and whether the relay port is reachable any other way.
- The website in `site/`, the GitHub Actions and release pipeline, image signing, and the supply chain beyond the
  advisory check (`cargo deny` licences, bans and sources, and a review of `aws-lc-rs`, `hyper`, `reqwest` and `rusqlite`
  themselves).
- Apple's side: how Apple treats a provider that sends many tokens it rejects, which is the reason for the unverified
  device quota and the strike breaker, and was not measured.
- Dynamic behaviour: no request was sent to a running relay, nothing was fuzzed, and the capacity figures (connections,
  memory, database stalls) were not measured.

## Notes for operators

- **Content type.** Every request with a body must say `Content-Type: application/json`, or it gets `415`. Check the
  Hedgerow app before releasing it; vole-kit already does.
- **New limit.** `max_inflight_per_addr` (default 64) can be set in the limits file. If every client looks like the
  proxy (the proxy is missing from `PP_TRUSTED_PROXIES`), they share this cap, and the relay logs a warning once an hour.
- **Compose.** Update the `tmpfs` line to `/tmp:size=16m,noexec,nosuid,nodev` on the next deploy. Nothing was deployed
  as part of this review.
- **Proxy.** Confirm the proxy appends the client address to `X-Forwarded-For` and that its own per-address connection
  and request limits are on; PIG-03 and PIG-08 depend on them.
