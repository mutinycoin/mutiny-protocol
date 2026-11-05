# Build 8 development status

Recorded 2026-10-16. Build 8 remains an engineering candidate. This status is not a production release, formal lock, tag, deployment authorization or complete Windows/Linux qualification.

## Published baseline and source synchronization

The public baseline is `d9a4d3267065a499bb0137d879fe4eda327cbd72`, the September 11 Build 7.0 Candidate 2 merge. The historical published release remains Build 6.9. This documentation change does not promote Build 8 to production authority.

The accepted Linux projection has been reconstructed separately and verified against its accepted manifest: **2,269 files, 67,603,300 bytes**, source roster `ec1948bfbc13edc7417231d42e0dedb6c1fae490780300644bc543f4055457eb`. The complete frozen Desktop source is reconstructed and verified at **2,589 files, 76,247,045 bytes**, source-record SHA256 `689ff9834fcbb0eea7cb0a8e2072ae8dddb5088cec6975155db514bb68a39fac`. Its sorted SHA256/TAB/relative-path/LF roster is `c771a35ecf983a8d6c4299a4fac25d64d087d532926dd0cdedf158f4938db007`. The final 341-file internal owner publication matches every requested path, length and hash; five overlapping recovered files independently agree. No frozen Desktop payload remains missing.

The catalogs share 2,231 byte-identical files, have eight differing common files, 350 Desktop-only files and 30 Linux-only files. They are distinct platform projections. No single coherent combined source or final candidate is asserted. Their identities are recorded in [source provenance](docs/build8/source-provenance.json); [the difference review](docs/build8/platform-differences.md) accounts for all eight relationships. A local publication candidate preserves the two projections in separate directories rather than merging their security and replay changes into an untested combination.

The local integration now contains the approved source projection under `build8/linux/` and `build8/desktop/`: **4,769 files, 142,296,715 bytes** (Linux 2,230; Desktop 2,539). Its sorted SHA256/TAB/candidate-relative-path/LF roster is `b3127cc29b2676fb99b454851122837577ca51385fa6df9a445852f644c17258`; the full byte inventory is [source-roster.json](docs/build8/source-roster.json). Git blobs preserve the exact approved bytes without host newline/filter conversion. All eight platform variants remain separate; source security guards and machine identifiers remain unchanged.

The restored chain and supplementary helpers/documents are **TEST inputs only: synthetic, non-Genesis, no custody or physical-profile data; generator not located; fresh qualification required**. The restored package is not claimed to pass. Architect approved retention of the original machine identifiers and exact synthetic inputs on 2026-10-16. Their public disclosure is intentional; this does not make those original-host checks portable or qualify another installation.

The [reproducibility review](docs/build8/reproducibility-review.md) records the two restored chain copies and four exact Desktop supplements to Linux. Those supplements change Linux's publication identity relative to its frozen source; no platform code variants were merged. The 93 machine-path-bearing historical/operator records remain excluded. Both Chrony provenance comments use a repository-relative documentation path, with no operational configuration change. Existing V1 source and history remain preserved.

Source publication is still held for the conditional Vercel decision: automatic Preview deployment is authorized only after confirmation that this exact branch/PR is excluded from production/custom-environment tracking. No public branch or PR is asserted by this local status.

## Recorded qualification evidence

These are separate owner-recorded gates. The repository synchronization task did not rerun them or combine their counts into one qualification result.

| Gate | Recorded result | Remaining limit |
| --- | --- | --- |
| Shipping | 130 passed, 0 failed, 1 ignored | The ignored case remains unrun coverage. |
| TEST | 237 passed, 10 failed | Current peer/ABI coverage remains open. |
| Linux selected correctness controls | 35 passed | Selected controls do not establish a full platform campaign pass. |
| No-key launcher controls | Five independently verified passes | Synthetic launch/closure checks do not establish live wallet payment acceptance. |
| Live TEST attempt | Owner reports wallet refusal and closure at Node height 49 | No H100/H101 payment or restart acceptance. |

The ignored shipping case is `tests::non_test_binary_refuses_unexpected_arguments`. A separate Windows history performance failure remains open. Peer and ABI input preparations and source reviews do not replace the ten open executable tests.

The five no-key checks cover valid completion, nonzero exit, timeout, image mismatch and output overflow. The owner reports 60 independently verified evidence files and owned cleanup for those checks.

In the later live attempt, the owner reports that the wallet refused with `Windows wallet protection failed` and exited naturally with code 1. The Node then closed through its supported shutdown route with its last generated height at 49. No LAN connection or payment admission occurred. The owner's terminal evidence remains the authority for detailed closure; this status does not turn cleanup into payment/restart success.

## Publication and qualification boundaries

- Architect approved the unchanged machine identifiers and exact synthetic test-input scope. Private operator records remain excluded; existing license declarations and third-party notices are retained.
- Preserve the two platform projections and exact roster. Any later portability/security cleanup requires its own review, identity and qualification.
- The restored package requires fresh compilation and tests. Existing shipping/TEST/Linux results below belong to their recorded source projections, not this restored publication package.
- Before push or draft PR, confirm the project's production branch and absence of matching production/custom tracking rules for `integration/build8-source-20261016` and its PR. Automatic Preview deployment is conditionally authorized; no production promotion, main merge, release/tag, alias or protection/settings change is authorized.

## Deployment evidence

GitHub records a successful Vercel deployment at `2026-10-16T12:02:00Z` on the old September baseline SHA. Its deployment environment is labeled `Production`, while the API's `production_environment` boolean is false. Those fields do not establish current project branch rules or the live production alias. The observed deployment URL is <https://mutiny-protocol-3pyuwawha-mutiny-protocol.vercel.app>.

Automatic deployment behavior for the proposed integration branch remains unverified. A non-production branch name is insufficient evidence that a push or pull request cannot deploy. No production merge, release or tag is part of this synchronization work.

The CMO relayed a READY production deployment from main, a Rust framework, and existing project domains/protection. The report inferred main tracking and repository-root configuration; it did not return explicit ProductionBranch, RootDirectory or branch/PR rules. Treat it as third-party evidence. The remaining deployment decision concerns automatic Preview builds and assurance that this branch is not tracked for production/custom-environment deployment; no project setting change is proposed.
