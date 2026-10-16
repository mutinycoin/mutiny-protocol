# NTS source-set assessment V1 (DRAFT for the Architect)

Status: research record, DRAFT. Prepared 2026-10-03. Nothing here is an approved profile, a qualified ceiling or a production
identity. No code was built or run. Every web fact below was read from a page fetched on **2026-10-03** (retrieval date applies to
every URL cited unless a different date is stated).

Scope: the Architect-approved INITIAL NTS (RFC 8915) source set for configuration and qualification work:
**Cloudflare, Netnod, PTB, SIDN (time.nl)**. Context only (not proof): `CLOCK-PROFILE-PREPARATION-D1.md` section 3.

Labels: **VERIFIED** = stated on a page fetched this session (the fetch tool returns a model-made summary of the page; where the
exact wording matters it is quoted and should be re-read at the URL before freezing). **UNVERIFIED** = not found on a fetched primary
page (search snippets, third-party lists, memory, inference). **DERIVED** = my arithmetic or inference from VERIFIED facts.
**PROPOSED** = not approved. **Primary** = the operator's own page.

Architect fixed values used (not changed here): fresh-vote max uncertainty 1.0 s; total initial uncertainty U0 <= 250 ms; 24 h target.

---

## 1. Per-operator findings

### 1.1 Cloudflare

| Item | Finding | Status / source |
|---|---|---|
| Operator, jurisdiction | "Cloudflare, Inc. and its affiliates"; terms governed by California law, exclusive courts in San Francisco County, California | VERIFIED, https://www.cloudflare.com/website-terms/ (generic site terms; Time Services listed as an Online Service); https://developers.cloudflare.com/time-services/tos/ says use of the time services is under those terms (address San Francisco, CA) |
| NTS-KE / NTP hostname | `time.cloudflare.com` (single name for NTP and NTS) | VERIFIED, https://developers.cloudflare.com/time-services/nts/ and /ntp/usage/ |
| NTS-KE port | **NOT RESOLVED.** The Cloudflare NTS/NTP docs pages fetched state no port. The 2019 launch blog says "point it at time.cloudflare.com:1234" (VERIFIED as text, but dated and not confirmed current): https://blog.cloudflare.com/secure-time/. Cloudflare's (now unmaintained) `cfnts` repo README says the default NTS-KE port is 4460: https://github.com/cloudflare/cfnts (VERIFIED as the repo's default, not a statement about what production serves). Search results show chrony users reaching time.cloudflare.com with the plain `nts` option, i.e. default 4460, but that is third-party (UNVERIFIED). | Conflict between 1234 (blog) and 4460 (repo default). Config must be proven by a live NTS-KE test, which is a named gate. |
| NTP server names handed out via NTS-KE | Not documented. | UNVERIFIED (needs live capture of the NTS-KE server/port records) |
| AEAD / NTS version | Not stated on any fetched Cloudflare page. | UNVERIFIED (RFC 8915 defines NTS version 1 only; AES-SIV-CMAC-256 is the mandatory-to-implement AEAD per the RFC, from memory, not fetched) |
| Stratum / source | Blog: "All of our servers are synchronized with stratum 1 time service providers, and then offer NTP to the general public"; upstream is authenticated "using a shared symmetric key with our stratum 1 upstream servers", "geographically spread" (VERIFIED, blog). That implies the served stratum is 2 or more; the figure **3** is only from a community list (https://raw.githubusercontent.com/jauderho/nts-servers/main/README.md, fetched, third-party) and search snippets. Upstream operators are not named. | Stratum value 3: UNVERIFIED (not on a Cloudflare page). Upstream identity: not published on pages read. |
| Anycast / unicast | Anycast: "you can use our global anycast network to synchronize time from our closest server" | VERIFIED, https://developers.cloudflare.com/time-services/ntp/usage/ |
| Network / AS | AS13335, "Cloudflare", open peering policy, "a global anycast network" | VERIFIED, PeeringDB record https://www.peeringdb.com/api/net?asn=13335 (that this AS originates the time.cloudflare.com addresses was NOT tested) |
| **Leap-second behaviour** | **"Cloudflare does not implement leap smearing: NTP includes a Leap Indicator field and the kernel will apply the leap second correction at the appropriate time."** It also warns "Using servers that smear time along with servers that do not may lead to unpredictable and anomalous results." | **VERIFIED**, https://developers.cloudflare.com/time-services/ntp/ . This RESOLVES the draft's UNVERIFIED Cloudflare leap policy: step, no smear (policy statement). How far ahead the leap indicator is raised is not stated. |
| Usage terms / rate limits | Time services fall under the general Cloudflare website/online-services terms (provided "AS IS"/"AS AVAILABLE", no promises on quality, accuracy or reliability). Free ("for free", draft). No time-service-specific rate limit, SLA or commercial-use clause on the pages read. | VERIFIED (absence of a specific clause is as read through the summary), https://developers.cloudflare.com/time-services/tos/ and https://www.cloudflare.com/website-terms/ |
| Accuracy | None stated beyond the blog's remark on lower jitter from proximity. | VERIFIED as absence |

### 1.2 Netnod

| Item | Finding | Status / source |
|---|---|---|
| Operator, jurisdiction | Netnod, Sweden (operator of Swedish Distributed Time); monitored by RISE Research Institutes of Sweden; financed by the Swedish Post and Telecom Authority (PTS). The exact legal entity name/form (e.g. "Netnod Internet Exchange i Sverige AB") is not on the pages read. | VERIFIED for operator/country/funder: https://www.netnod.se/swedish-distributed-time-service , https://www.netnod.se/free-time-services . Legal entity name UNVERIFIED. |
| NTS-KE hostnames | `nts.netnod.se` (global/anycast); `gbg1/gbg2/lul1/lul2/mmo1/mmo2/sth1/sth2/svl1/svl2.nts.netnod.se` (Goteborg, Lulea, Malmo, Stockholm, Sundsvall; two each) | VERIFIED, https://www.netnod.se/nts/network-time-security . The older name `nts.ntp.se` appears in the 2019 launch article (https://www.netnod.se/time-and-frequency/netnod-launch-one-of-the-first-nts-enabled-time-services-in-the-world); the current NTS page does not mention it. Use `nts.netnod.se`. |
| NTS-KE port | **4460** is the official port; legacy 3443 and 4443 (earlier NTS drafts) "backwards compatible" | VERIFIED, https://www.netnod.se/nts/network-time-security |
| NTP port | **Non-default: 4123** ("Port 4123 (NTP with security)"), alongside outbound 4460. So NTP/NTS traffic is not on UDP 123. Whether 4123 is handed out in the NTS-KE port record for every hostname was not tested. | VERIFIED as stated, https://www.netnod.se/netnod-time/how-to-use-nts . Firewall rule must allow UDP 4123 (and TCP 4460). |
| NTP server names handed out via NTS-KE | Not documented (setup example just uses `server sth1.nts.netnod.se nts iburst`). | UNVERIFIED (needs live capture) |
| AEAD / NTS version | Not stated; clients: chrony >= 4.0, NTPsec >= 1.2.0 | AEAD UNVERIFIED; client versions VERIFIED, https://www.netnod.se/netnod-time/how-to-use-nts |
| Stratum / source | "Stratum-1 time servers", time traceable to UTC(SP); each site has redundant servers, two caesium clocks and two FPGA boards (custom FPGA NTP responders, 10 Gb/s line rate). 2019 article: "traceable to within 250 nanoseconds of official Swedish time UTC(SP)" (a 2019 claim, not a current SLA). | VERIFIED, https://www.netnod.se/free-time-services , https://www.netnod.se/swedish-distributed-time-service , 2019 launch article above. Whether UTC(SP) is itself steered by GNSS is not stated on pages read (UNVERIFIED). |
| Anycast / unicast | Anycast `nts.netnod.se` (and `ntp.se` for plain NTP); regional hostnames are per-site (two per city; the unicast nature of the NTS regional names is as described by the operator for the unicast addresses, anycast used "to mitigate DoS") | VERIFIED, https://www.netnod.se/swedish-distributed-time-service , /free-time-services |
| Network / AS | **AS57021**; IPv4 194.58.200.0/24 to 194.58.207.0/24; IPv6 2a01:3f7:0::/48 to 2a01:3f7:7::/48. Note: the page says "six distributed nodes" while other pages say five sites: inconsistency in operator text. | VERIFIED as stated, https://www.netnod.se/swedish-distributed-time-service |
| **Leap-second behaviour** | **Not stated** on any Netnod page fetched (NTS page, free-time-services, distributed-time, how-to-use-nts, launch article). Custom FPGA responder: behaviour not documented. | **UNVERIFIED. Cannot be resolved from fetched pages.** |
| Usage terms / rate limits | "free to anyone, anywhere"; no usage policy, rate limit or SLA text on pages read. Contact noc@netnod.se. | VERIFIED as stated, https://www.netnod.se/free-time-services (absence of terms as read) |
| Accuracy | Only the 2019 UTC(SP) 250 ns traceability claim (above). | VERIFIED as a 2019 operator claim |

### 1.3 PTB (Physikalisch-Technische Bundesanstalt)

| Item | Finding | Status / source |
|---|---|---|
| Operator, jurisdiction | PTB, Germany; the national metrology institute; statutory duty to realise and disseminate legal time (EinhZeitG para 6 (2), quoted in the PTB document) | VERIFIED, https://zeit.ptb.de/files/Zeitserver_der_PTB_v1.0.pdf (German, "Stand: 12.02.2026", version 1.0, text extracted locally with pdftotext) |
| NTS-KE hostnames | `ptbtime1.ptb.de`, `ptbtime2.ptb.de`, `ptbtime3.ptb.de` (Braunschweig), `ptbtime4.ptb.de` (Berlin, "separate location") | VERIFIED, https://zeit.ptb.de/files/ptb-ntp-services.json (release date 2026-03-03, v1.0); https://www.ptb.de/cms/en/ptb/fachabteilungen/abt9/gruppe-95/ref-952/time-synchronization-of-computers-using-the-network-time-protocol-ntp.html (names, ptbtime4 at a separate location) |
| NTS-KE port | **4460/TCP** (NTS-KE, initial TLS channel); **123/UDP** NTP. No non-default port. This RESOLVES the draft's UNVERIFIED PTB port. | VERIFIED, PDF technical table and JSON above |
| NTP server names handed out via NTS-KE | Not documented. NTS-KE and NTP run "on the same machine" (PDF: Diensttrennung), which suggests the KE host serves NTP itself, but the NTS-KE record contents were not captured. | UNVERIFIED (inference; needs live capture) |
| AEAD / NTS version | Not stated. NTP/NTS is served by chrony; chrony version not stated. TLS minimum 1.3; certificates from Let's Encrypt. | AEAD UNVERIFIED; chrony, TLS 1.3 minimum, Let's Encrypt VERIFIED (JSON and PDF) |
| Stratum / source | **Stratum value not stated on any PTB page or file.** PDF: servers synchronise to "the atomic clocks located at PTB", connection redundant, primary time sources redundant; self-monitoring switches a server off when the offset from the primary sources grows too large. | Stratum value UNVERIFIED (cannot be resolved; the draft's "1" came from a community list only). Source description VERIFIED. |
| Anycast / unicast | Four named servers, two sites (Braunschweig x3, Berlin x1); no anycast mentioned. Reachable over IPv4 and IPv6. ICMP ping disabled. | VERIFIED as described (anycast: not stated, treat as unicast) |
| Network / AS | Not stated ("redundant per server"). | UNVERIFIED |
| **Leap-second behaviour** | **Not stated** (PDF, JSON and the English NTP page contain no mention of leap seconds or smearing). DERIVED/inference only: the PDF states chrony is used, and chrony does not smear unless `smoothtime`/`leapsecmode` is configured (chrony docs, fetched in the earlier draft session); the PTB configuration is not published at that level. | **UNVERIFIED. Cannot be resolved from fetched pages.** |
| Usage terms / rate limits | Free, no registration; "cannot be held liable" for damage from failure or delay; "we cannot guarantee permanent and disturbance free operation". **Rate limiting: disabled** (both NTP and NTS). Maintenance on one server at a time. Contact ntp-admin@ptb.de (English page) / ntpadmin@ptb.de (JSON). | VERIFIED, English NTP page, PDF, JSON |
| Accuracy / reference | Self-shutdown when offset from primary sources exceeds **10 ms**; auto-recovery after the offset has stayed below 10 ms for at least 5 minutes; NTS typically degrades sync accuracy by < 100 microseconds; statistics kept 15 years. PDF: NTS gives no legally binding statement and no guarantee the time is correct. | VERIFIED as operator statements (a 10 ms trip threshold is not an accuracy guarantee) |

### 1.4 SIDN Labs (time.nl)

| Item | Finding | Status / source |
|---|---|---|
| Operator, jurisdiction | "Brought to you by SIDN Labs", "the research team of SIDN (the .nl registry administrator)"; Netherlands. Location Arnhem (SIDN Labs page; SIDN named as "Stichting Internet Domeinregistratie Nederland" in search results). Service labelled "(experimental)" in the liability sentence; page footer "all rights reserved, no warranty, no liability". | Operator/country VERIFIED: https://time.nl/ , https://nts.time.nl/ , https://www.sidnlabs.nl/en . Legal form (Stichting) and address: UNVERIFIED from a primary fetched page (search results only). Note SIDN Labs is a team within SIDN, not a separate legal entity as far as the pages show. |
| NTS-KE hostnames | Production: `ntppool1.time.nl`, `ntppool2.time.nl`. Pre-production: `ntppool3.time.nl`, `ntppool4.time.nl`. Also `ntspool.time.nl` (pool name), `any.time.nl` (anycast, stratum 2), `nts1.time.nl` (original pilot, "not recommended ... in a production environment"; experimental NTS server running Chrony 4.8-2ubuntu1 "NOT SUITABLE for serious use"). The page recommends ntppool1/2 for production. | VERIFIED, https://nts.time.nl/ and https://time.nl/ . NTS available in production "since early 2022" (time.nl, Dutch text). |
| NTS-KE port | Not documented on the pages read; default 4460 expected but not stated. | UNVERIFIED |
| NTP server names handed out via NTS-KE | Not documented. | UNVERIFIED (note that `ntspool.time.nl` is a pool name; the draft says it can span other operators: not re-verified, avoid it) |
| AEAD / NTS version | Not stated. | UNVERIFIED |
| Stratum / source | "consists of four stratum 1 servers" (nts.time.nl). ntppool1/2: primary **Galileo+GPS**, secondary **DCF77 + rubidium holdover**. ntppool3/4: **UTC(VSL)** atomic clocks + rubidium holdover. time.nl also describes GPS, Galileo, DCF77, Dutch atomic clocks at VSL in Delft and Belgian atomic clocks, with a rubidium holdover against spoofing. | VERIFIED, https://nts.time.nl/ , https://time.nl/ . This RESOLVES the draft's stratum for SIDN (1 for the production servers). |
| Anycast / unicast | Production servers are named unicast hosts; `any.time.nl` is the anycast experiment ("dozens of servers distributed worldwide"). | VERIFIED, https://time.nl/ |
| Network / AS | Not stated on pages read. | UNVERIFIED |
| **Leap-second behaviour** | **No smearing**: "we geen zogenaamde 'leap smearing' doen" (we do not do so-called leap smearing). Advance leap indicator behaviour not described. | **VERIFIED (no smear)**, https://time.nl/ |
| Usage terms / rate limits | "Use of this service is entirely at your own risk" ("geheel voor eigen risico"); SIDN (Labs) not liable for damage from use or inability to use its (experimental) services. Fair use: typical NTP poll ~1024 s keeps users well within limits; ~30 min suffices for scheduled sync; "occasional temporary deviations" acceptable; operator asks users not to abuse. No numeric rate limit. | VERIFIED, https://time.nl/ |
| Accuracy | No numeric accuracy statement found on pages read. | VERIFIED as absence |

---

## 2. Draft items from CLOCK-PROFILE-PREPARATION-D1.md section 3: resolved or not

| Draft left UNVERIFIED | Result |
|---|---|
| Cloudflare leap policy | RESOLVED: no smearing, step via Leap Indicator (Cloudflare developers page). Warning on mixing smearing and non-smearing servers (same page). |
| PTB port / endpoint | RESOLVED: ptbtime1..4.ptb.de, NTS-KE 4460/TCP, NTP 123/UDP, TLS >= 1.3, Let's Encrypt (PTB PDF and JSON). |
| SIDN stratum | RESOLVED: stratum 1 for ntppool1/2 (and 3/4); production = ntppool1/2. |
| Netnod stratum | RESOLVED: "Stratum-1" (Netnod free-time-services page). |
| Netnod port | RESOLVED: NTS-KE 4460 (legacy 3443/4443), NTP/NTS on **4123** (non-default). |
| Cloudflare stratum | NOT RESOLVED from a Cloudflare page. Blog says upstream is stratum 1 (so served stratum >= 2); "3" is third-party only. |
| Cloudflare NTS-KE port | NOT RESOLVED: 1234 (2019 blog) vs 4460 (cfnts default). Requires live test. |
| PTB stratum | NOT RESOLVED: no PTB document states it. |
| Netnod, PTB leap behaviour | NOT RESOLVED: not stated anywhere fetched. |
| SIDN NTS-KE port | NOT RESOLVED (not stated). |
| AEAD for all four | NOT RESOLVED: no operator page states it. |
| NTP hostnames handed out via NTS-KE (all four) | NOT RESOLVED: needs a live NTS-KE exchange (named qualification gate). |
| Operator ASNs | Verified only for Cloudflare (13335, PeeringDB) and Netnod (57021, Netnod page); PTB and SIDN not verified. |

Draft correction: the draft table suggested using `ptbtime1.ptb.de` "port 4460 is from a search summary only"; it is now primary-verified. The draft also lists the NTS name `nts.ntp.se` for Netnod as unchecked; current Netnod docs use `nts.netnod.se`.

---

## 3. (a) Source-diversity analysis

Rule applied: several addresses or hostnames of one operator count as **ONE operator**. Cloudflare = 1 (one anycast name, one AS), Netnod = 1 (anycast + ten regional names), PTB = 1 (four hosts, two sites), SIDN = 1 (ntppool1..4; any.time.nl; nts1). So the approved set has **4 operators**.

Operator independence (legal / jurisdiction / network):

| Operator | Legal / jurisdiction | Class | Network |
|---|---|---|---|
| Cloudflare | Cloudflare, Inc. (US, California law) | Commercial CDN, anycast fan-out of upstream stratum-1 | AS13335 VERIFIED |
| Netnod | Netnod (Sweden), publicly funded by PTS | IX operator, own caesium clocks, UTC(SP) | AS57021 VERIFIED |
| PTB | German federal metrology institute | National metrology institute, atomic clocks on site | UNVERIFIED |
| SIDN | SIDN (.nl registry; SIDN Labs team), Netherlands | Registry research team; GNSS and VSL atomic clocks | UNVERIFIED |

Distinct legal entities and distinct jurisdictions (US, SE, DE, NL): VERIFIED at country level from the operators' own pages. Distinct ASes: VERIFIED only for Cloudflare vs Netnod; PTB and SIDN not verified (cannot claim 4 distinct ASNs).

Shared upstream risks:

VERIFIED or documented:
* SIDN ntppool1/2 take **Galileo + GPS** as primary. A GNSS-wide fault or spoofing/jamming event common to GPS and Galileo is a documented dependency of SIDN; SIDN states DCF77 and rubidium holdover as backups and UTC(VSL) for ntppool3/4.
* PTB, Netnod and SIDN ntppool3/4 trace to separate national/lab clocks (UTC(PTB) atomic clocks "located at PTB"; UTC(SP) at Netnod; UTC(VSL) for SIDN 3/4). Different laboratories, different clock ensembles per the pages.
* PTB depends on Let's Encrypt certificates (PTB PDF). That is a shared **authentication** dependency with any other server using Let's Encrypt, not a time-reference dependency. Certificate authorities of the other three operators were not read.
* All four are reached over the public Internet and TLS WebPKI; BGP and DNS faults or hijacks of the client's path are common to all.
* The client's chrony/RFC 8915 implementation is common to all.

NOT verifiable (cannot claim independence):
* Cloudflare's upstream stratum-1 providers are not named on pages read. They could be any of the other three operators or a GNSS-fed provider; common-mode risk with the others therefore cannot be excluded.
* Whether UTC(SP) at Netnod is GNSS-steered (it likely realises UTC(k) with GNSS-assisted links, but this is not stated on fetched pages: UNVERIFIED), and whether PTB's "primary time sources" include GNSS or only the lab clocks (UNVERIFIED; the PDF says atomic clocks at PTB, redundant).
* UTC(k) laboratories are all steered toward UTC through BIPM, which is a long-term (monthly) coupling, not a short-term common failure; stated here as background knowledge, not from a fetched page.
* PTB and SIDN ASNs, transit paths, and physical co-location with others (e.g. both could sit behind the same IX or transit): not verified.
* Cloudflare's anycast catchment may route the Node to a PoP in the same facility/IX as another operator: not tested.

Concentration: three of four operators are in Europe (SE, DE, NL); one is global. A European-wide or EU-routed network event, or the clients' own ISP, is a single point for three. Node B (Vultr) path and Node A path were not measured.

Conclusion (DERIVED): the set gives four distinct operators and four jurisdictions, which meets the D1 "at least three independent" recommendation on legal/jurisdictional grounds, but source independence at the *time-reference* level is only partly evidenced: SIDN GNSS-based, others lab/atomic, Cloudflare undisclosed.

---

## 4. (b) PROPOSED source-agreement and failure assumptions (NOT approved)

All items in this section are PROPOSED for the Architect. Numbers are limited to the Architect's fixed ones; any other threshold is labelled.

**P-A1 (independence unit).** One operator = one vote regardless of how many hostnames/addresses it exposes. (Current code counts selected addresses, not operators: `host_clock.rs:145-157, 223` per the draft; that is a gap to decide, not assumed fixed.)

**P-A2 (minimum agreement).** At least **3 distinct operators** must be authenticated (NTS) and agree before a calibration sample is accepted; the 4th is for availability, so one operator may be down or excluded and the quorum still holds. The "3" follows from D1's "at least three independent servers" recommendation, with `n >= 2f+1` for f = 1 tolerated faulty/excluded operator (this combination is PROPOSED, requires Architect).

**P-A3 (agreement tolerance).** Operators agree when the uncertainty intervals of at least the required number of operators have a common intersection, each interval built from that source's own measured offset plus its own root dispersion/delay, where each source interval is at most the fresh-vote cap of 1.0 s and the combined result must meet the total initial U0 of 250 ms. No separate pairwise millisecond tolerance is invented here; if one is wanted: **PROPOSED, requires Architect or measurement** (a measurement of inter-operator offsets from Node A / Node B is the way to choose it). The operators' own statements (for example PTB's 10 ms self-shutdown, Netnod's 2019 250 ns claim) are not usable as bounds: they are operator claims, not evidence of what the node receives over the Internet.

**P-A4 (minority faulty / malicious / smearing).** With 4 operators and f = 1, a single outlier source (faulty reference, malicious or compromised server, smearing source, hijacked path, stale or wrong time) is rejected by the intersection rule and must not move the result. Two or more disagreeing operators (f >= 2) means no quorum: no new calibration is accepted and the clock continues only on its last anchor under the holdover rules (the existing engine behaviour: draft section 1e), eventually going Unqualified. A rejected source is recorded as a fault with the operator, not silently dropped. Note that f = 1 does NOT protect against a common-mode event across several operators (shared GNSS, shared path, section 3).

**P-A5 (disagreement above the uncertainty bound).** If the combined interval would be wider than allowed, or the operators' intervals have no common intersection of the required size: reject the calibration (do not widen the bound to fit, do not average), keep the previous anchor, log it. A class/node is never given a looser bound to make sources agree (consistent with D1: UNQUALIFIED rather than a looser bound).

**P-A6 (authentication plus agreement do not prove the uncertainty bound).** NTS authenticates *who* sent the time and that it was not modified in transit; agreement shows several authenticated sources are mutually consistent. Neither proves the claimed uncertainty. Reasons, each supported by fetched text:
 * PTB's own document says NTS gives "no legally binding statement" and no guarantee the transmitted time is correct, and that NTS protects integrity/authenticity, not correctness (PTB PDF).
 * Operators publish no accuracy SLA; all four disclaim liability (Cloudflare "AS IS", PTB "cannot be held liable ... deviations", SIDN "at your own risk", Netnod free service with no terms read).
 * NTS does not authenticate against delay or asymmetric routing: a path attacker can delay authenticated packets without breaking the MAC (general NTP/NTS property, not from a fetched page here; the PTB PDF says NTS is only a transport protection and its accuracy cost is < 100 microseconds, nothing about delay attacks).
 * Several operators can be wrong together (shared GNSS, shared upstream; section 3).
 Therefore the uncertainty bound must be derived from the client's own measured quantities (offset, root dispersion, root delay/2, sampling window; draft 1e.2) plus a margin, and the bound itself is accepted only through measurement/qualification, never because sources authenticate and agree. The agreement check is a necessary filter, not the proof.

**P-A7 (leap-smear sources excluded or bounded).** A source that smears must be excluded from the set, unless its ambiguity is explicitly bounded and counted in the uncertainty. Verified facts supporting this:
 * Cloudflare publishes that mixing smearing and non-smearing servers "may lead to unpredictable and anomalous results" (developers.cloudflare.com/time-services/ntp/).
 * Cloudflare states it does NOT smear and uses the Leap Indicator; SIDN states it does NOT smear (time.nl). So these two are step sources by operator statement.
 * Netnod and PTB: leap behaviour not stated (UNVERIFIED). They cannot be assumed non-smearing.
 * DERIVED: a step source and a smear source differ by up to one full second around the event, because a leap second is exactly 1 s; the fresh-vote cap is 1.0 s and U0 is 250 ms, so such a spread is not inside U0 and cannot be hidden in the uncertainty.
 * chrony smears on the server side only if configured (`smoothtime`/`leapsecmode`); the FAQ says it is meant for local networks (chrony FAQ, fetched).

> **SUPERSEDED BY docs/CLOCK-PROFILE-V1.md section 4 (Architect ruling 4, 3 Oct 2026): the margin was removed; the
> ambiguous zone is derived.** Applies to the interaction with `LEAP_MARGIN_MS = 1000` named at the end of the next
> paragraph (note added 3 Oct 2026; the paragraph is kept unchanged).

 Proposed handling: (1) before enabling Netnod and PTB for production, obtain the operators' written leap policy (ask noc@netnod.se, ntp-admin@ptb.de) or observe it at the next leap event; until then treat them as "leap behaviour unknown"; (2) for a window around a pending or recent leap second, **PROPOSED, requires Architect**: accept calibration only from operators whose non-smearing behaviour is verified (Cloudflare, SIDN) or hold on the last anchor; the length of that window is **PROPOSED, requires Architect or measurement**; (3) any source observed to disagree by about 1 s that tracks the leap event is excluded and the operator flagged. The interaction with `LEAP_MARGIN_MS = 1000` is the open item already in draft section 1e.3. Leap seconds are also currently not scheduled for insertion after 2016 per IERS announcements, which I did not verify here; so do not rely on absence of a leap event.

**P-A8 (re-verification).** Each operator fact in section 1 marked UNVERIFIED must be confirmed by a live NTS-KE exchange (server/port/AEAD records) and operator contact before the source set is frozen; qualification is a separate gate, not shown here.

---

## 5. Verified vs not: summary

VERIFIED from fetched primary pages: Cloudflare hostname, anycast, no-smear leap policy, terms (generic, "AS IS"), legal entity/jurisdiction, AS13335 (PeeringDB, third-party registry); Netnod hostnames, NTS-KE 4460 (legacy 3443/4443), NTP port 4123, stratum-1, caesium clocks, UTC(SP), AS57021, anycast+unicast, free service; PTB hostnames, 4460/TCP and 123/UDP, TLS 1.3 minimum, Let's Encrypt, chrony, rate limiting disabled, 10 ms self-shutdown, atomic clocks at PTB, liability disclaimer, no registration; SIDN hostnames, stratum 1, reference clocks (Galileo+GPS, DCF77, UTC(VSL), rubidium holdover), no leap smearing, fair-use and at-your-own-risk terms, anycast only for any.time.nl.

NOT verified / cannot resolve: AEAD algorithms and NTS-KE record contents for all four; NTP names handed out via NTS-KE for all four; Cloudflare NTS-KE port (1234 vs 4460) and stratum value; PTB stratum value, leap behaviour, ASN; Netnod leap behaviour and legal entity name; SIDN NTS-KE port, ASN and legal form; advance leap-indicator behaviour for all (only Cloudflare mentions use of the Leap Indicator, no timing); any numeric rate limit; upstream providers of Cloudflare; whether UTC(SP)/PTB references are GNSS-steered.

Sources (all retrieved 2026-10-03): developers.cloudflare.com/time-services/{nts/,ntp/,ntp/usage/,tos/}; blog.cloudflare.com/secure-time/; github.com/cloudflare/cfnts; cloudflare.com/website-terms/; peeringdb.com/api/net?asn=13335; netnod.se/{nts/network-time-security, free-time-services, swedish-distributed-time-service, netnod-time/how-to-use-nts, time-and-frequency/netnod-launch-one-of-the-first-nts-enabled-time-services-in-the-world}; ptb.de English NTP page; zeit.ptb.de/files/{Zeitserver_der_PTB_v1.0.pdf, ptb-ntp-services.json}; time.nl; nts.time.nl; sidnlabs.nl/en; gitlab.com/chrony/chrony faq.adoc; raw.githubusercontent.com/jauderho/nts-servers/main/README.md (third-party).
