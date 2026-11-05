# Ordinary Treasury verifier application

Architect's production-disabled ordinary application root. The Linux binary and
library share the same private native owner, bounded readers and authenticated
continuity implementation. This root is a shipping component; its `cfg(test)`
installation fixture is excluded from its ordinary graph and executable.

`Client::open` accepts an already replayed CanonicalStore plus bounded sealed
transport custody in erasing ownership. It authenticates the independently
installed record before custody/network/storage effects. `issue`, `admit` and
explicit `reconcile` use the same native owner tested in the retained APP46
campaign. `Service::open` and `open_reconciling` use its matching existing-only
service and protected history. `serve_ready` drives one serialized bounded
request; it adds no daemon, retry, nonce TTL or consensus dependency.

The executable's `service-check`, `reconcile-service` and `serve-ready` commands
call this same Service API with erasing framed input. `serve-ready` waits for and
authenticates at most one request: waiting and exchange share the exact installed
I/O budget. It closes afterward and adds no daemon, logical retry or new budget.
A missing NORMAL compiled installation
refuses before stdin read with exit78. Authentic installed configuration remains
absent: NORMAL enrollment is None and production is disabled. Public proof/schema,
operation commitments and key rotation are unchanged. No Treasury spending keys
enter this service or application.

This adoption draft has not compiled or run against the consolidated dependency
tree. The retained 46 controls belong to the exact earlier source, not this
facade or relocation. Existing native tests remain; the shared-entry control is
adapted to call the ordinary public facade, reopen the same identities, restore
an older local database and reconcile only exact retained external history. One
additional native control exercises authenticated request/response through the
actual finite executable dispatch; the successor has 47 selected controls
(38 native, nine modeled enrollment/dispatch controls), presently unrun.

Native storage is presently Linux-only. There is no implicit Windows fallback.
Protected deployment administration and power-loss qualification remain separate
from software checks. The complete frozen campaigns must include this root's
NORMAL graph/build/fixture-exclusion and ordinary facade controls with actual
source and runner identities.
