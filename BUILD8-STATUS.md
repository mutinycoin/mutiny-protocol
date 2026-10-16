# Build 8 development status

Recorded 2026-10-16. Build 8 remains an engineering candidate. This status is not a production release, formal lock, tag, deployment authorization or complete Windows/Linux qualification.

## Published baseline and source synchronization

The public baseline is `d9a4d3267065a499bb0137d879fe4eda327cbd72`, the September 11 Build 7.0 Candidate 2 merge. The historical published release remains Build 6.9. This documentation change does not promote Build 8 to production authority.

The accepted Linux projection has been reconstructed separately and verified against its accepted manifest: **2,269 files, 67,603,300 bytes**, source roster `ec1948bfbc13edc7417231d42e0dedb6c1fae490780300644bc543f4055457eb`. The complete frozen Desktop source is reconstructed and verified at **2,589 files, 76,247,045 bytes**, source-record SHA256 `689ff9834fcbb0eea7cb0a8e2072ae8dddb5088cec6975155db514bb68a39fac`. Its sorted SHA256/TAB/relative-path/LF roster is `c771a35ecf983a8d6c4299a4fac25d64d087d532926dd0cdedf158f4938db007`. The final 341-file internal owner publication matches every requested path, length and hash; five overlapping recovered files independently agree. No frozen Desktop payload remains missing.

The catalogs share 2,231 byte-identical files, have eight differing common files, 350 Desktop-only files and 30 Linux-only files. They are distinct platform projections. No single coherent combined source or final candidate is asserted. Their identities are recorded in [source provenance](docs/build8/source-provenance.json); [the difference review](docs/build8/platform-differences.md) accounts for all eight relationships. A local publication candidate preserves the two projections in separate directories rather than merging their security and replay changes into an untested combination.

The source payloads have not been added by this documentation change. Public source synchronization remains held for the exact machine-identity disclosure decision and verified Vercel deployment rules. The local candidate is separate from the exact frozen snapshots; its explicit omissions and comment-only path changes require their own reproducible manifest. Existing V1 source and history are preserved.

The local paired projection contains 4,763 files (2,225 Linux and 2,538 Desktop), 141,023,286 bytes. All candidate paths, lengths and hashes were rechecked; 88 license/notice files are retained. The [projection review](docs/build8/publication-projection.json) records 95 omissions and the comment-only changes. Static inspection finds test dependencies on the withheld chain fixture and two withheld documents; one further relative fixture include needs verification against the frozen source. Consequently this projection is not yet a build-ready source commit. Restore only classified public test inputs, or use owner-reviewed replacements with explicit new identities, before claiming reproducibility.

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

## Conditions before source publication

- Preserve the eight platform source differences or obtain a reviewed coherent integration; do not silently select one version.
- Exclude generated chain state, private logs, keys, vaults, credentials, machine-private records and generated build caches. Retain applicable source licenses, notices and public test vectors.
- Resolve the public classification of the existing machine-bound Windows installation and fixed TEST-control literals, including the additional Desktop principal, custody-path prefix and installed-file identity found in the complete snapshot. Preserve security guards; do not redact or generalize the checks without review and a new source identity.
- Verify the connected Vercel project's production branch, project root and exact branch/PR deployment rules before any push or PR that could deploy.

The existing root license declaration is unchanged. No new license terms are introduced by this documentation change.

## Deployment evidence

GitHub records a successful Vercel deployment at `2026-10-16T12:02:00Z` on the old September baseline SHA. Its deployment environment is labeled `Production`, while the API's `production_environment` boolean is false. Those fields do not establish current project branch rules or the live production alias. The observed deployment URL is <https://mutiny-protocol-3pyuwawha-mutiny-protocol.vercel.app>.

Automatic deployment behavior for the proposed integration branch remains unverified. A non-production branch name is insufficient evidence that a push or pull request cannot deploy. No production merge, release or tag is part of this synchronization work.
