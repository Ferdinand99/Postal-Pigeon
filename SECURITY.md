# Security Policy

## Status

Postal Pigeon (the Hedgerow push relay) is in the design phase. **It is not ready for use**, and there is no released
code to attack yet. The apps do not depend on it.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Once it is enabled, report it privately through GitHub's
[private vulnerability reporting](https://github.com/Ferdinand99/Hedgerow-Relay/security/advisories/new): go to
the repository's **Security** tab and click **Report a vulnerability**. Only you and the maintainer can see the
report. Until it is enabled, contact the maintainer through their
[GitHub profile](https://github.com/Ferdinand99) and ask for a private channel before sharing details.

Please include what the issue is and where, how to reproduce it, and the impact you think it has.

At this stage, flaws in the published design (the API, the privacy statement and the [threat model](docs/design.md#16-threat-model))
are as welcome as flaws in code. Once the service exists, these are in scope: the relay's API and its handling of
credentials, handles and device tokens, rate-limit and abuse-control bypasses, anything that lets one server reach a
device it was not given a handle for, anything that reveals which server a device belongs to, and any way to make a
push carry content.

Out of scope: Apple's push service itself, volumetric denial-of-service floods against a single small host, and
weaknesses in servers or apps that use the relay (report those to their own repositories).

## No external audit

Postal Pigeon has not been independently audited and no external audit is funded. Security work is done in the
open and reviewed internally. The design keeps the relay small and content-free on purpose, so that a mistake in it
costs as little as possible; see the [threat model](docs/design.md#16-threat-model).
