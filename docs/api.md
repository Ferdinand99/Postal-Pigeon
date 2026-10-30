# Postal Pigeon API, version 1

This is the reference for people who write an app or a server that uses the relay. The reasons behind the rules are in
[`design.md`](design.md); where the two differ in wording, this page describes what the code does.

## Conventions

- JSON over HTTPS. Every path starts with `/v1`. A request with a body must say `Content-Type: application/json`
  (a charset is fine); any other type, or none, is refused with `415 unsupported_media_type`, so that a web page cannot
  post to the relay on a visitor's behalf. The relay sends no CORS headers.
- Request bodies are at most **2 KiB** (`413 too_large` above that). Unknown fields are ignored.
- Authentication is `Authorization: Bearer <secret>`.
- Errors look like `{"error": "<code>", "message": "<text>"}`. The code is stable; the text is for people. A `429` or
  `503` carries a `Retry-After` header in seconds.
- Secrets are random and prefixed so a leaked one is recognisable: `hrk_` (instance credential), `hrd_` (device id, not
  secret), `hrm_` (manage key), `hrh_` (handle). The relay stores only their SHA-256.
- No response ever contains a device token.
- A wrong or unknown credential is charged to the caller's address (60 an hour by default) and answers `429` once the
  address has used them up; a request with valid credentials is never held up by that, so clients behind a shared address
  are not locked out by someone else's bad requests.

| Error code | Status | Meaning |
|---|---|---|
| `invalid_request` | 400 | A field is missing or out of range; the message names it. |
| `invalid_challenge`, `challenge_expired`, `challenge_used`, `invalid_proof` | 400 | Registration proof of work failed (see below). |
| `invalid_credentials` | 401 | The secret is missing, malformed or wrong. |
| `unknown_instance` | 401 | The instance credential is well formed but the relay does not know it (for example after a database loss). Register again. |
| `suspended` | 403 | The instance is suspended. Do **not** register again; tell the administrator. |
| `not_found` | 404 | No such device or handle. |
| `method_not_allowed` | 405 | The path does not take that method. |
| `limit_reached` | 409 | A device already has the most handles it may have (32). |
| `too_large` | 413 | The body is over 2 KiB. |
| `unsupported_media_type` | 415 | The body is not sent as `application/json`. |
| `rate_limited` | 429 | A limit applies, or the address has too many requests running at once. Wait `Retry-After` seconds. |
| `overloaded` | 503 | The relay is busy or full; retry later. |

## Health and status

- `GET /healthz` answers `200 ok` when the process is up and the database answers, else `503`. Nothing else is revealed.
  `GET /` answers the same, for reverse proxies that health-check `/` by default.
  This is what Vigilant Vole and the container health check use.
- `GET /v1/status` answers `{"api": [1], "apns": "ok" | "degraded" | "unknown", "version": "..."}`. `apns` reflects
  recent real sends, not a call to Apple. `degraded` means the relay's own access to Apple is in trouble (the provider
  token or topic is refused, Apple told the relay to back off, or too many devices answered "bad token" at once, which
  pauses deleting devices), not that your push failed. `registration` is `normal` or `busy`; `busy` means many instances
  registered today and the proof of work is harder until midnight UTC (see the limits).

## Instances (self-hosted servers)

Registration is open. A new instance can send nothing until a user gives it a handle, and starts in the "new" tier with
lower limits.

### `GET /v1/challenge`

```json
{ "challenge": "...", "difficulty": 20, "expires_at": "2026-10-27T12:05:00Z" }
```

The challenge is valid for five minutes and works once. `difficulty` is the number of leading zero bits to find and **rises
with recent registration volume** (the relay asks for more work when many instances register within an hour); it is
fixed when the challenge is issued, so use the value in the response. An address or network that has used up its daily
registrations gets `429` here instead of a challenge.

### `POST /v1/instances`

```json
{ "challenge": "...", "nonce": "...", "product": "vigilant-vole", "version": "0.14.0" }
```

Find a `nonce` (any string of at most 64 ASCII characters, for example a counter in decimal) such that
`SHA-256(challenge || nonce)` has at least `difficulty` leading zero bits. The hash input is the UTF-8 bytes of the
challenge string followed by the UTF-8 bytes of the nonce string. At 20 bits this takes about a second.

```python
import hashlib, itertools
def solve(challenge, difficulty):
    for n in itertools.count():
        digest = hashlib.sha256(challenge.encode() + str(n).encode()).digest()
        if int.from_bytes(digest, "big") >> (256 - difficulty) == 0:
            return str(n)
```

`product` is one of `vigilant-vole`, `keen-kestrel`, `wise-wren`, `faithful-ferret`, `sylo`; `version` is optional, at most 32
characters of `A-Z a-z 0-9 . _ + -`. Both are informational.

`201`:

```json
{
  "instance_credential": "hrk_...",
  "tier": "new",
  "limits": { "sends_per_hour": 600, "handles_per_request": 25, "unknown_handles_per_hour": 20 }
}
```

The credential is shown once. Keep it sealed in your own database. The relay never asks for your address or name.

### `POST /v1/instances/self/rotate` (instance credential)

Returns `{"instance_credential": "hrk_..."}` and invalidates the old credential at once.

### `DELETE /v1/instances/self` (instance credential)

Removes the registration. `204`.

## Devices and handles (the app)

A device is one app install. The app registers its APNs token **directly with the relay** and gives each of its servers
an opaque handle. The relay stores the token sealed, and never links a device or a handle to an instance.

### `POST /v1/devices`

```json
{ "app": "hedgerow", "environment": "production", "token": "<hex device token>" }
```

`app` must be one the relay is configured for. `environment` is `production` or `sandbox` (development builds from Xcode
use the sandbox; TestFlight and the App Store use production) and must be one the relay allows. `token` is hexadecimal,
32 to 200 bytes. `201`: `{"device_id": "hrd_...", "manage_key": "hrm_..."}`.

If a record for the same token exists it is **replaced**: its device id and handles stop working. Keep the manage key
in the keychain, on this device only.

### `PUT /v1/devices/{device_id}` (manage key)

Body `{"token": "...", "environment": "..."}`, both optional. Sets a new token when APNs hands the app one, and counts as
a keep-alive; call it on launch, at most once a day. `204`, or `404` if the record is gone (register again and issue
new handles). A device that is not heard from for 90 days is deleted.

### `DELETE /v1/devices/{device_id}` (manage key)

Removes the device and every handle. `204`.

### `POST /v1/devices/{device_id}/handles` (manage key)

Body `{"tag": "<16 random bytes as unpadded base64url>"}`. The tag is echoed back in the push so the app can tell which
connection a push belongs to. `201`: `{"handle_id": "...", "handle": "hrh_..."}`. At most 32 handles per device and 10
creations per hour. Give the `handle` to one server over the connection you already have with it.

### `GET /v1/devices/{device_id}/handles` (manage key)

```json
{ "handles": [ { "handle_id": "...", "tag": "...", "created": "2026-10-27", "last_used": "2026-10-27" } ] }
```

`last_used` is a date (no time of day) or `null`. The secret is never shown again.

### `DELETE /v1/devices/{device_id}/handles/{handle_id}` (manage key)

Revokes one handle at once; the relay then answers `gone` for it. `204`, or `404`.

## Sending (the instance)

### `POST /v1/push` (instance credential)

```json
{
  "event_id": "7f6c8e0e-5d1b-4a43-9d3e-0c1d9b1b2a77",
  "handles": ["hrh_...", "hrh_..."],
  "kind": "alert",
  "ref": "inc_9f3a1c",
  "collapse": "inc_9f3a1c",
  "ttl": 3600
}
```

| Field | Rule |
|---|---|
| `event_id` | Required, a UUID. A push Apple accepted is not sent again for the same instance, event and handle within 15 minutes (`duplicate`). A push that failed can be retried with the same id. |
| `handles` | 1 to 25 handles. The same push goes to all. A handle listed twice is sent once; the repeat answers `duplicate`. |
| `kind` | `alert`: a visible notification with fixed, generic text from the app. `sync`: a silent "fetch now". Which kinds an app may use is set on the relay. |
| `ref` | Optional opaque id, at most 64 of `A-Z a-z 0-9 _ -`. Use random ids, not counters. |
| `collapse` | Optional, at most 32 of the same characters. For alerts, pushes from the same handle with the same value replace each other at Apple. Apple sees only a keyed hash of the handle and the value, so another server (another handle) can never replace your alerts by choosing the same value. (Syncs collapse per handle.) |
| `ttl` | Optional seconds to keep trying, 60 to 86400. Defaults: alert 3600, sync 900. |

`200`, with one result per handle, in order:

```json
{ "results": [ { "status": "accepted" }, { "status": "gone" }, { "status": "limited", "retry_after": 600 } ] }
```

| Status | Meaning and what to do |
|---|---|
| `accepted` | Apple took the push. This is not a promise that the device got it. |
| `duplicate` | This `event_id` was already sent to that handle. Nothing was sent. |
| `gone` | The handle is unknown, revoked, or its device is no longer valid. **Forget the handle.** The answer is the same for "never existed" and "revoked". |
| `limited` | A limit applies to this handle or device (or to a device Apple has asked the relay to back off from). Retry no sooner than `retry_after` seconds, or drop the push. |
| `unavailable` | Apple or the relay could not deliver now. A retry later may work. `retry_after` is present when Apple has told the whole relay to pause (then nothing is sent to anyone until then). |
| `unsupported_kind` | The device's app does not accept this `kind` (for example `alert` for Faithful Ferret). Treat unknown statuses as `unavailable`. |

Whole-request failures: `400 invalid_request`, `401 invalid_credentials` or `unknown_instance`, `403 suspended`,
`413 too_large`, `429 rate_limited`, `503 overloaded`. A `429` is the instance's hourly limit, or too many unknown
handles: an instance may present at most 20 handles per hour that do not exist (or are revoked). **If a request holds more
unknown handles than the instance has left of that allowance, the whole request is refused with `429` and nothing in it
is sent** (the unknown ones are what is counted, but the refusal is all or nothing, and the instance is flagged for
review). Forget handles that answered `gone` so they are not presented again. The relay calls Apple while you wait and
answers within about five seconds. There is no queue: send in a background task and give up when the push would have
expired.

### What the push contains

The relay builds the push itself; you cannot add text. An `alert` carries the app's fixed `loc-key`s
(`HR_PUSH_TITLE`, `HR_PUSH_BODY`), `mutable-content` (so the app's Notification Service Extension can replace the text
with details fetched from the user's own server), the default sound and the handle's tag as `thread-id`. A `sync` is a
silent `content-available` push. Both carry `{"hr": {"v": 1, "k": "<kind>", "t": "<tag>", "r": "<ref>"}}`; `r` is
left out without a `ref`. Alerts use priority 10 and expire after `ttl`; syncs use priority 5 (Apple requires it for
background pushes).

## Limits

The numbers below are the defaults (design section 10) and can be changed by the operator with a JSON file named by
`PP_LIMITS_FILE`; any field may be left out. They are token buckets kept in memory.

| Limit | Default |
|---|---|
| Instance registration | proof of work (`pow_difficulty`, 20 bits, plus up to `pow_adaptive_max_extra_bits` = 8 more: one bit for each doubling of the last hour's registrations above `pow_adaptive_threshold_per_hour` = 30); `instance_reg_per_addr_day` 5 per address (IPv6 /64); `instance_reg_per_prefix_day` 25 per network (IPv4 /24, IPv6 /48); `instance_reg_high_water_per_day` 5000 relay-wide: registration is never closed, but above it the work asked for rises by `pow_high_water_extra_bits` = 4 more bits until midnight UTC, `/v1/status` shows `"registration": "busy"` and the log says so |
| Device registration | `device_reg_per_addr_hour` 20, `device_reg_per_addr_day` 100 per address; `device_reg_per_prefix_hour` 100, `device_reg_per_prefix_day` 500 per network; `max_devices` 1,000,000 rows (registering a known token is always allowed; when the table is full, the oldest records that have no handle, never had a push accepted and are more than an hour old are removed to make room, and the registration is refused with `503` only if there are none) |
| Devices Apple never accepted | `unverified_device_per_hour` 3 sends per hour, until the first push is accepted |
| Handles | `handle_create_per_device_hour` 10, `max_handles_per_device` 32 |
| Device updates | `device_update_per_hour` 20 per device |
| Send per handle | alert `alert_per_handle_hour` 6 (burst `alert_handle_burst` 3); sync `sync_per_handle_hour` 30 (burst `sync_handle_burst` 5) |
| Send per device | `alert_per_device_hour` 30; `sync_per_device_hour` 120 |
| Send per instance | `send_per_instance_hour_new` 600; `send_per_instance_hour_established` 6000 (after `established_after_days` = 7 without limit hits) |
| Unknown handles per instance | `unknown_handles_per_instance_hour` 20 |
| Auto-suspension | more than `auto_suspend_throttled_per_day` = 1000 `429`s in a day |
| Wrong credentials per address | `auth_failures_per_addr_hour` 60 |
| Toward Apple | `app_sends_per_second` 100 per app (burst twice that) |
| Strike breaker | `strike_trip_devices` 10 devices that have had a push accepted before, on behalf of at least `strike_trip_instances` 3 different instances, answering `BadDeviceToken` and the like within `strike_window_secs` 600, making up `strike_trip_percent` 50 of an app's answers, stop all striking and deleting for `strike_trip_secs` 3600 |
| Other | `max_handles_per_request` 25, `challenge_ttl_secs` 300, `max_tracked_keys` 100,000 per limiter (the least recently used are dropped when full), `max_inflight_requests` 2048 (plus `health_inflight_requests` 16 for `/` and `/healthz` only), `max_inflight_per_addr` 64 requests running at once per address (an IPv6 /64), `max_connections` 4096, `header_read_timeout_secs` 10; a request line and headers over 16 KiB get `431` |

## Versioning

Changes within `/v1` are additive: new optional fields, new response fields, new error codes and new `kind` values.
Ignore fields you do not know, and treat an unknown result status as `unavailable`. A breaking change gets `/v2` beside
`/v1`; see design section 15.
