# Synthetic fixtures

Everything in this directory is invented. There is no real organisation, no real
person, no real host and no real credential here.

Conventions that keep it that way:

- Domains use `example` / `.example`, reserved by RFC 2606 for documentation.
- IPv4 addresses come from `203.0.113.0/24` and `198.51.100.0/24`, reserved by
  RFC 5737 as TEST-NET ranges.
- Cloud resource identifiers name a fictional account (`000000000000`).
- No file here contains a credential, a token or a key — real or fabricated.
  Secrets appear only as *identifiers* of a secret (`sec-billing-api-key`),
  never as a value.

The fictional organisation is **Halberd Logistics**, a mid-size company with a
billing portal, a payments service and an archive bucket.

| File | Purpose |
|---|---|
| `asset-inventory.json` | Baseline Security Graph: declared assets and the relationships between them that exist independently of telemetry. Loaded at startup. |
| `scenario-01-identity-compromise.json` | The five-step demo attack chain. Replayed through the real ingest API by `make demo`. |

Scenario timestamps are rebased at replay time so the demo always produces a
current incident rather than one that ages out of the ingest window.
