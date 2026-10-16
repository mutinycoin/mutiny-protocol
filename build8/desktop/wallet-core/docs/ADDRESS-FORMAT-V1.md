# Address text format V1 (`MUTINY-BUILD8-ADDRESS-TEXT-V1`)

**Status: PROPOSED, NOT frozen.** Order W2 (Build 8 Architect continuation order, 2026-10-04):
"Deliver a reviewed checksummed, network-distinguishing display/import format before production
wallet acceptance. Retain full-address validation and signed destination binding." This document
specifies the format implemented in `wallet-core/src/address_format.rs`; it is not frozen until the
Architect approves it, and the vectors in `tests/golden/address-format-v1.json` are TEST-VALUE public
vectors. Registered in `spec/DOMAIN-REGISTRY-V1.json` as `PROPOSED-UNFROZEN`.

**Evidence.** Implemented is not Qualified. Everything below is backed by code and by tests that ran
offline on Windows (NATIVE PASS, offline, TEST-VALUE at most). No Linux, physical or production run.

## 1. What is encoded

An address is the 32-byte AddressID `SHA-256("MUTINY-BUILD8-HYBRID-ADDRESS-V1" || 0 || descriptor)`
of a wallet descriptor at a generation (`crypto-v2/src/lib.rs`, `PublicKey::address_id`). The
AddressID is what a transaction output names, what an operation signs and what consensus compares.
The text form is ONLY an encoding of those 32 bytes for a person: nothing signs the text, nothing
stores it in place of the bytes, and decoding yields exactly the 32 bytes that were encoded
(`decode` never truncates, completes or prefix-matches; tested by
`address_format::tests::every_rejection_class_has_its_own_typed_error`). Every request type keeps a
32-byte `Hash` field; the wallet's existing validation of that field (for example the refusal of the
all-zero recipient, `INVALID_RECIPIENT`) is unchanged.

## 2. The encoding

```text
address-text = prefix "1" data checksum           ; lowercase only
prefix       = "mut" / "tmut" / "umut"             ; section 3
data         = 52 characters                        ; the 32 bytes as 5-bit groups
checksum     = 6 characters                         ; bech32m (BIP-350)
```

* The 32 bytes are read as 256 bits, most significant bit first, and cut into 52 groups of five
  bits; the last group is completed with four ZERO bits (260 bits). Each group is written with the
  BIP-173 alphabet `qpzry9x8gf2tvdw0s3jn54khce6mua7l` (`CHARSET`): value `v` is the character
  `CHARSET[v]`.
* The checksum is the BCH code of BIP-173 (`bech32_polymod` with the generator coefficients
  `0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3`, `GENERATOR`) over the expanded prefix
  (`bech32_hrp_expand`: the high three bits of each prefix byte, a zero, the low five bits) followed by
  the data values, with the bech32m constant of BIP-350, `0x2bc830a3` (`CHECKSUM_CONSTANT`). A string is
  valid when the polymod of expanded prefix, data and checksum equals that constant.
* Lengths: 62 characters with `mut`, 63 with `tmut` or `umut`, within the BIP-173 limit of 90.
* The implementation is cross-checked against the published strings: the seven valid bech32m
  strings of BIP-350 verify with the constant and the five valid bech32 strings of BIP-173 verify
  with the bech32 constant 1 (`address_format::tests::the_published_bip350_and_bip173_strings_verify_with_their_constants`,
  and again from the vector file in `tests/address_format_vectors.rs`).

Example (the public TEST-VALUE key A, the all-"abandon" BIP-39 phrase, generation 1; identifier
`1c1e598337dc5a49749c465232dadcfc745fb389217d4aed4072654c2bd2187c`):

| Chain class | Text |
|---|---|
| production | `mut1rs09nqehm3dyjayugefr9kkul369lvufy9754m2qwfj5c27jrp7qldkksg` |
| TEST-VALUE | `tmut1rs09nqehm3dyjayugefr9kkul369lvufy9754m2qwfj5c27jrp7qj23q3m` |
| not declared | `umut1rs09nqehm3dyjayugefr9kkul369lvufy9754m2qwfj5c27jrp7q83yr7f` |

## 3. The prefix: what it distinguishes, and what it cannot

The prefix names the CLASS that the wallet's VERIFIED chain declares in its Treasury record
(`ChainView::class`, `src/context.rs`): `mut` for a production-class chain, `tmut` for a
TEST-VALUE-class chain, `umut` for a chain that declares no class (no Treasury record). A build, a
feature or a configuration never chooses it, and a chain that declares nothing is never labelled
production or TEST-VALUE: the wallet cannot know a class the chain does not state. All three
prefixes are defined for network `0x4d555401` only (`NETWORK_ID`, the ASCII bytes `MUT` and the
version byte 1); a compile-time assertion in `address_format.rs` fails if the consensus or crypto-v2
network identifier changes, so a new network cannot silently reuse them.

Distinguishable from the text alone:

* the class the ENCODING wallet's verified chain declared, and this network. A decoder refuses a
  string whose prefix is not the one of its own verified chain's class (`WRONG_PREFIX`). The main
  hazard this addresses: a TEST-VALUE address may belong to a public test key (anyone can spend
  from it); it cannot be entered into a production wallet by accident, and a production address
  cannot be entered into a TEST-VALUE wallet
  (`address_format::tests::the_same_identifier_reads_differently_under_each_class_and_a_prefix_edit_breaks_the_checksum`);
* a prefix edited by hand: the checksum covers the prefix, so changing `mut` to `tmut` gives
  `INVALID_CHECKSUM`, never a valid address of the other class (same test).

NOT distinguishable:

* two chains of the same class (two TEST-VALUE chains, or a production chain and a re-run of it):
  Genesis is not encoded;
* the identifier itself: it is derived from the key's descriptor and the network identifier only,
  so the same key has the same identifier on every chain of this network, whatever the prefix;
* who produced a string: anyone can encode any 32 bytes under any prefix. The checksum detects
  accidents; it is not authentication.

## 4. Decoding is strict

`decode_any(text)` checks, in this order, and stops at the first failure; `decode(text, class)` then
requires the prefix of `class`; `decode_for(text, view)` uses the view's verified class and returns
the wallet refusal `ADDRESS_ENCODING` carrying the error. Every failure is a distinct
`AddressError` with a stable code (`AddressError::code`); none carries the entered text.

| Order | Rule | Error code |
|---|---|---|
| 1 | not empty | `EMPTY` |
| 2 | at most 90 characters | `TOO_LONG` |
| 3 | every character printable ASCII (33 to 126): no space, control or non-ASCII character; nothing is trimmed | `INVALID_CHARACTER` |
| 4 | one case only | `MIXED_CASE` |
| 5 | lowercase: the all-uppercase form BIP-350 permits for QR codes is refused, not lower-cased (no silent normalisation) | `UPPERCASE` |
| 6 | a separator `1` (the last `1` of the string) | `MISSING_SEPARATOR` |
| 7 | the prefix is `mut`, `tmut` or `umut` (an empty prefix is not) | `UNKNOWN_PREFIX` |
| 8 | every data character is in the alphabet | `INVALID_CHARACTER` |
| 9 | at least the six checksum characters | `TOO_SHORT` |
| 10 | the bech32m checksum verifies | `INVALID_CHECKSUM` |
| 10 | (a string whose checksum is a BIP-173 bech32 checksum instead) | `CHECKSUM_VARIANT` |
| 11 | exactly 52 data characters | `PAYLOAD_TOO_SHORT`, `PAYLOAD_TOO_LONG` (extra data) |
| 12 | the four padding bits are zero (the canonical encoding of the 32 bytes) | `NON_CANONICAL_PADDING` |
| 13 | `decode` only: the prefix is the expected class's | `WRONG_PREFIX` |

The class is compared only for a well-formed address: a wrong-class string with a damaged checksum
is `INVALID_CHECKSUM` (`address_format::tests::the_check_order_is_the_documented_one`). Every single
substitution of a data or checksum character, and every swap of two adjacent different characters, is
detected (`address_format::tests::every_single_substitution_and_adjacent_transposition_is_detected`).

## 5. The legacy hexadecimal form

The 64 lowercase hexadecimal characters of the identifier remain an explicit LEGACY and diagnostic
form: `legacy_hex` writes it and `parse_legacy_hex` reads exactly 64 characters `0-9a-f`
(`LEGACY_HEX_LENGTH`, `LEGACY_HEX_CHARACTER`; uppercase is refused, nothing is trimmed). It has no
checksum and no class. The checksummed form is the primary display and import: `encode`/`decode`.

## 6. Where the format is used

* **Display.** Every structured address row of a review (`Review::rows`, `render_text`: signing
  address, wallet authority, required wallet authorizations, parties, destinations, fee payer) shows
  the checksummed form of the review's verified class FIRST, then `legacy hex <64 characters>`
  (`src/review.rs`, `show_address` and `show_labelled`). The desktop draws exactly these rows
  (`desktop/src/plan_review.rs`). A maker party is named by the hash of its trade identity, which is
  not an address: it is shown as hexadecimal with "the maker's trade identity, not an address" and
  never in the address form. Golden snapshots: every `tests/golden/*_review.txt`.
* **Import.** `decode_for(text, view)` (or `decode(text, class)`) is the primary import for a host;
  the result is the 32-byte identifier a request takes.
* **Not yet.** The desktop's own input forms still parse 64-character hexadecimal
  (`desktop/src/operation_screens.rs`, the desktop lane), and the free-text conditions, effects and
  summaries of the operation handlers still name addresses in hexadecimal (a short or full form);
  the structured rows above are the primary display. Both are listed as open in
  `docs/WALLET-OPERATIONS-V1.md` section 6.

## 7. The typed destination check: kept, unchanged, as an interim aid

Decision (W2, Q10): the typed destination check stays exactly as it was (the person types the last
eight hexadecimal characters of each destination that is not this wallet's own,
`Destination::check_text`, `ReviewGate::confirm_destination`). It is an interim human-error aid, NOT
a checksum and NOT address authentication.

Why it is kept on top of a checksummed address. The checksum and the typed check guard against
different mistakes. The checksum catches a CORRUPTED address when it is entered or pasted: a typo,
a dropped or swapped character. It cannot catch a WRONG but well-formed address (an address book
entry for someone else, a clipboard replaced by malware, a look-alike): such an address carries a
valid checksum. Only a comparison of the address about to be signed with the person's own record of
the address they intend can notice that, and the typed check is the step that puts that address in
front of the person at review time, on the bytes the plan actually binds. It does not prove the
comparison happened: the eight characters are shown next to the field, and the typed checks are
ordinary calls a host process holding the key could make itself (`README.md`, "What the gates are,
and what they are not"). So it adds an attention step, not security; retiring it would remove that
step for no gain in safety, and would change the desktop's review flow, which is the desktop lane's
(W15).

Why hexadecimal characters. The check text is a function of the 32 bytes alone, independent of the
chain class, so `Destination::check_text` keeps its meaning for the review gate and for the desktop,
and each review row shows the legacy hexadecimal form next to the checksummed one, so the eight
characters to type are visible in context (the last eight of that form). Eight hexadecimal characters
are 32 bits: they defeat carelessness and look-alikes, not a determined attacker who generates about
2^32 candidate keys to match them.

Proposal (open question for the Architect): switch the typed characters to the last eight characters
of the checksummed form (40 bits, and the characters a person sees first) in the same change that
moves the desktop's review screens to the checksummed form.

## 8. Vectors

`tests/golden/address-format-v1.json` (TEST-VALUE, public): 21 valid encodings (seven identifiers,
three of them the addresses of the public TEST-VALUE keys A, B and C of `tests/support/synthetic.rs`,
under all three classes), 21 rejections covering every decoder error, legacy hexadecimal vectors,
and the published BIP-350 and BIP-173 strings. `tests/address_format_vectors.rs` decodes and encodes
every vector (`the_published_vectors_decode_and_encode_exactly`), proves the file is exactly the
output of its generator (`the_vector_file_is_the_generators_output`; the ignored
`print_address_format_vectors` prints it), and that the format is registered once as
`PROPOSED-UNFROZEN` (`the_format_is_registered_as_proposed_and_unfrozen`).

## 9. Not done

* Not frozen: the prefixes, the alphabet, the order of the checks and the error codes may change
  until the Architect approves this document.
* No Linux, physical or production run; no independent second implementation (the published
  BIP-350/BIP-173 strings are the independent check of the checksum core).
* The desktop's input forms and the handlers' free-text mentions of addresses are not converted
  (section 6).
