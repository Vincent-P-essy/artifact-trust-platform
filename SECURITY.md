# Security policy

## Supported versions

Only the latest commit on `main` receives security fixes during pre-1.0 development.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include live credentials, exploit
payloads, private repository contents or personal data in any report. Use GitHub private
vulnerability reporting for this repository. Include:

- affected version or commit;
- impacted trust boundary or security invariant;
- minimal inert reproduction;
- expected and actual behavior;
- whether signing material, source data or queue state could be exposed.

A report should be acknowledged within seven days. Remediation timing depends on severity and
whether a safe workaround exists. Public disclosure should wait until a fix and migration guidance
are available.

## Safe deployment baseline

- keep `ATP_ALLOW_NETWORK=0` unless pinned Git acquisition is required;
- expose the API only through authenticated TLS termination;
- run API and worker as different unprivileged services;
- preserve the read-only root filesystem, dropped capabilities and `no-new-privileges` settings;
- mount signing keys read-only and distribute public keys independently;
- keep the work volume private and apply retention controls;
- pin container bases, external scanner versions and vulnerability databases in production;
- review any policy/advisory change like code and rerun golden and tamper tests.

## Test data

`tests/keys` is public, deterministic test material. `rejected-app` contains a documented
non-live credential example so the redaction path can be tested. Neither is a secret.
