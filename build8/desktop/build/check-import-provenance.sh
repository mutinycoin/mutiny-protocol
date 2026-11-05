#!/usr/bin/env bash
# Import-provenance check for the identity-verified imports recorded in build/imports/.
#
# What it establishes: every file that entered the tree through an explicit, identity-verified import
# (the wallet and release signer, commit 121479b; the release-signer public fixture) is still byte-identical
# to what was imported, OR its difference is explicitly recorded. Nothing is tolerated silently.
#
# Inputs (all under build/imports/):
#   IMPORT-MANIFEST-*.sha256     sha256sum-format manifests, one per import (never edited after the import).
#   IMPORT-COMMITS-V1.tsv        one line per manifest: manifest file, the manifest's own sha256, the import
#                                commit (full 40 hex) that introduced the manifest and the files it lists.
#   EDITED-AFTER-IMPORT-V1.tsv   the EXPLICIT record of later legitimate changes (its header describes the
#                                format). A file that differs from its manifest line and is not listed there
#                                is a FAILURE; so is a listed entry that no longer matches the tree.
# Checks:
#   1  every IMPORT-MANIFEST-*.sha256 is recorded, its own sha256 equals the recorded value, its lines are well formed
#   2  git mode: the import commit exists, is an ancestor of HEAD, and the manifest blob AND every listed file's blob
#      at that commit hash to the manifest value (the manifest is a true description of what was imported)
#   3  every listed file in the tree is identical to its manifest line, or has a matching 'edited' record (current
#      sha256 equal to the tree) or a 'removed' record; any other difference fails
#   4  the record itself is consistent (no stale entry for an unchanged file, no entry for an unknown file)
#   5  every file under desktop/ and release-signer/ is covered by a manifest or an 'added' record; no private or
#      generated evidence (target/, *.sqlite*, *.wallet, *.dpapi, *.tpm-private, *.test-value-backup, NODE-A-*,
#      *LIVE-TPM*, qualification/*PRIVATE*) exists in the imported, wallet-core or qualification trees
#   6  the imported public fixture still says synthetic:true and production_authorized:false and has no secret-named key
# Modes: inside a git work tree (a .git entry at the tree root) all of the above. In an extracted package (no .git)
#   check 2 is SKIPPED explicitly (the package manifest covers file identity; build-package.sh runs this script against
#   the repository at build time) unless BUILD8_PROVENANCE_GIT_DIR names a git directory that holds the import commits.
# Usage: build/check-import-provenance.sh [--propose]
#   --propose  after the checks, print the EDITED-AFTER-IMPORT lines that WOULD cover every unrecorded difference.
#              It never writes anything; adding a line is an explicit act that a reviewer sees in the diff.
# Requires bash 4+ (associative arrays). Exit status 0 only if no check failed. Implemented != Qualified; this is an
# offline identity check.
set -u
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMP="$ROOT/build/imports"
COMMITS_REC="$IMP/IMPORT-COMMITS-V1.tsv"
EDITS_REC="$IMP/EDITED-AFTER-IMPORT-V1.tsv"
PROPOSE=0
while [ $# -gt 0 ]; do
  case "$1" in --propose) PROPOSE=1 ;; *) echo "unknown option $1" >&2; exit 64 ;; esac; shift
done
FAIL=0; PASS=0; SKIP=0
pass() { PASS=$((PASS+1)); echo "  PASS  $*"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $*"; }
skip() { SKIP=$((SKIP+1)); echo "  SKIP  $*"; }
sha() { local o; o="$(sha256sum "$1")"; printf '%s' "${o:0:64}"; }
HEX64='^[0-9a-f]{64}$'
HEX40='^[0-9a-f]{40}$'
PROPOSALS=""
propose() { PROPOSALS="$PROPOSALS$(printf '%s\t%s\t%s\t%s\tTODO: state the reason\n' "$1" "$2" "$3" "$4")"$'\n'; }

# ---- mode ---------------------------------------------------------------------------------------
MODE=package; GIT=()
if [ -e "$ROOT/.git" ] && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  MODE=git; GIT=(git -C "$ROOT")
elif [ -n "${BUILD8_PROVENANCE_GIT_DIR:-}" ] && git --git-dir="$BUILD8_PROVENANCE_GIT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  MODE=package-with-history; GIT=(git --git-dir="$BUILD8_PROVENANCE_GIT_DIR")
fi
echo "== Import provenance (mode: $MODE; git work tree = git, extracted package = package)"

# ---- records ------------------------------------------------------------------------------------
declare -A REC_SHA REC_COMMIT          # manifest file name -> recorded manifest sha256 / import commit
declare -A INMANIFEST MSHA MSRC        # repo path -> 1 / manifest-listed sha256 / manifest file name
declare -A EDIT_CUR EDIT_IMP EDIT_KIND # repo path -> recorded current sha256 / import sha256 / kind
declare -A TREESHA                     # repo path -> sha256 of the file in the tree (filled in one process)
BADREC=0
if [ ! -f "$COMMITS_REC" ]; then fail "build/imports/IMPORT-COMMITS-V1.tsv is missing"; BADREC=1
else
  while IFS=$'\t' read -r mf msha mcommit extra; do
    case "$mf" in ''|'#'*) continue ;; esac
    if [ -n "${extra:-}" ] || ! [[ "$msha" =~ $HEX64 ]] || ! [[ "$mcommit" =~ $HEX40 ]]; then
      fail "IMPORT-COMMITS-V1.tsv: malformed line for '$mf' (need: manifest file, sha256, 40-hex commit)"; BADREC=1; continue; fi
    if [ -n "${REC_SHA[$mf]:-}" ]; then fail "IMPORT-COMMITS-V1.tsv: '$mf' is recorded twice"; BADREC=1; continue; fi
    REC_SHA[$mf]=$msha; REC_COMMIT[$mf]=$mcommit
  done < <(tr -d '\r' < "$COMMITS_REC")
fi
# every manifest present must be recorded, and every recorded manifest must be present
for f in "$IMP"/IMPORT-MANIFEST-*.sha256; do
  [ -f "$f" ] || continue
  b="${f##*/}"
  if [ -z "${REC_SHA[$b]:-}" ]; then fail "$b exists but is not recorded in IMPORT-COMMITS-V1.tsv"; BADREC=1; fi
done
REC_NAMES=""
if [ "${#REC_SHA[@]}" -gt 0 ]; then
  REC_NAMES="$(printf '%s\n' "${!REC_SHA[@]}" | sort)"
  while IFS= read -r b; do
    [ -f "$IMP/$b" ] || { fail "$b is recorded in IMPORT-COMMITS-V1.tsv but the file is missing"; BADREC=1; }
  done <<< "$REC_NAMES"
else fail "no import manifest is recorded"; BADREC=1; fi

if [ ! -f "$EDITS_REC" ]; then fail "build/imports/EDITED-AFTER-IMPORT-V1.tsv is missing (it may have no entries, but it must exist)"; BADREC=1
else
  while IFS=$'\t' read -r kind path isha csha reason; do
    case "$kind" in ''|'#'*) continue ;; esac
    case "$kind" in edited|removed|added) ;; *) fail "EDITED-AFTER-IMPORT-V1.tsv: unknown kind '$kind' for '$path'"; BADREC=1; continue ;; esac
    ok=1
    case "$kind" in
      edited)  { [[ "$isha" =~ $HEX64 ]] && [[ "$csha" =~ $HEX64 ]]; } || ok=0 ;;
      removed) { [[ "$isha" =~ $HEX64 ]] && [ "$csha" = "-" ]; } || ok=0 ;;
      added)   { [ "$isha" = "-" ] && [[ "$csha" =~ $HEX64 ]]; } || ok=0 ;;
    esac
    if [ "$ok" = 0 ] || [ -z "${reason:-}" ] || [ -z "$path" ]; then
      fail "EDITED-AFTER-IMPORT-V1.tsv: malformed '$kind' line for '$path' (need: kind, path, import sha256, current sha256, reason)"; BADREC=1; continue; fi
    case "$path" in /*|*..*|*\\*) fail "EDITED-AFTER-IMPORT-V1.tsv: unsafe path '$path'"; BADREC=1; continue ;; esac
    if [ -n "${EDIT_KIND[$path]:-}" ]; then fail "EDITED-AFTER-IMPORT-V1.tsv: '$path' is recorded twice"; BADREC=1; continue; fi
    EDIT_KIND[$path]=$kind; EDIT_IMP[$path]=$isha; EDIT_CUR[$path]=$csha
  done < <(tr -d '\r' < "$EDITS_REC")
fi

# ---- 1,2: manifests ------------------------------------------------------------------------------
# blob_hashes <commit> <paths...>: sha256 of each path's blob at the commit, in ONE git + ONE sha256sum process
# (git archive into a temp dir). The caller re-verifies any mismatch with the exact blob (git cat-file), so an
# archive conversion or export attribute can only cause a slower path, never a wrong answer.
declare -A BLOBSHA
blob_hashes() {
  local commit="$1" tmp line; shift
  BLOBSHA=()
  tmp="$(mktemp -d 2>/dev/null)" || return 0
  if "${GIT[@]}" archive --format=tar "$commit" -- "$@" 2>/dev/null | tar -x -C "$tmp" 2>/dev/null; then
    while IFS= read -r line; do BLOBSHA[${line:66}]="${line:0:64}"; done < <(cd "$tmp" && sha256sum -- "$@" 2>/dev/null | tr -d '\r')
  fi
  rm -rf "$tmp"
}
NIMPORTED=0
while IFS= read -r b; do
  [ -n "$b" ] || continue
  mf="$IMP/$b"; [ -f "$mf" ] || continue
  commit="${REC_COMMIT[$b]}"
  got="$(sha "$mf")"
  if [ "$got" = "${REC_SHA[$b]}" ]; then pass "$b: manifest sha256 equals the recorded value (${got:0:12}...)"
  else fail "$b: manifest sha256 $got != recorded ${REC_SHA[$b]} (the manifest was altered)"; fi
  # well-formedness: sha256sum format (hash, two spaces, path), safe relative paths, no duplicates
  bad=0; n=0; MPATHS=()
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    n=$((n+1))
    h="${line:0:64}"; sep="${line:64:2}"; p="${line:66}"
    if ! [[ "$h" =~ $HEX64 ]] || [ "$sep" != "  " ] || [ -z "$p" ]; then fail "$b: malformed line $n"; bad=1; continue; fi
    case "$p" in /*|*..*|*\\*|*' '*) fail "$b: unsafe or unexpected path '$p'"; bad=1; continue ;; esac
    if [ -n "${INMANIFEST[$p]:-}" ]; then fail "$b: '$p' is listed twice (also in ${MSRC[$p]})"; bad=1; continue; fi
    INMANIFEST[$p]=1; MSHA[$p]=$h; MSRC[$p]=$b; MPATHS+=("$p")
  done < <(tr -d '\r' < "$mf")
  NIMPORTED=$((NIMPORTED+n))
  if [ "$n" = 0 ]; then fail "$b: no lines"
  elif [ "$bad" = 0 ]; then pass "$b: $n lines, all well formed with unique relative paths"; fi
  # the import commit
  if [ "${#GIT[@]}" = 0 ]; then
    skip "$b: import commit ${commit:0:12} not checked (no git history in this extracted package; build-package.sh runs this check against the repository at build time)"
    continue
  fi
  if ! "${GIT[@]}" cat-file -e "$commit^{commit}" 2>/dev/null; then
    fail "$b: import commit ${commit:0:12} is not available in this repository (shallow clone or wrong repository)"; continue; fi
  if [ "$MODE" = git ]; then
    if "${GIT[@]}" merge-base --is-ancestor "$commit" HEAD 2>/dev/null; then pass "$b: import commit ${commit:0:12} exists and is an ancestor of HEAD"
    else fail "$b: import commit ${commit:0:12} is not an ancestor of HEAD"; fi
  else pass "$b: import commit ${commit:0:12} exists in the supplied history"; fi
  rel="build/imports/$b"
  blob_hashes "$commit" "$rel" "${MPATHS[@]}"
  bs="${BLOBSHA[$rel]:-}"
  if [ "$bs" != "${REC_SHA[$b]}" ] && "${GIT[@]}" cat-file -e "$commit:$rel" 2>/dev/null; then bs="$("${GIT[@]}" cat-file blob "$commit:$rel" | sha256sum | cut -c1-64)"; fi
  if [ "$bs" = "${REC_SHA[$b]}" ]; then pass "$b: the manifest blob at the import commit equals the recorded sha256"
  else fail "$b: the manifest blob at ${commit:0:12} hashes to ${bs:-<missing>}, not the recorded ${REC_SHA[$b]}"; fi
  nbad=0
  for p in "${MPATHS[@]}"; do
    bs="${BLOBSHA[$p]:-}"
    if [ "$bs" != "${MSHA[$p]}" ]; then
      if "${GIT[@]}" cat-file -e "$commit:$p" 2>/dev/null; then bs="$("${GIT[@]}" cat-file blob "$commit:$p" | sha256sum | cut -c1-64)"
      else fail "$b: '$p' does not exist at the import commit"; nbad=$((nbad+1)); continue; fi
    fi
    if [ "$bs" != "${MSHA[$p]}" ]; then fail "$b: '$p' at the import commit hashes to $bs but the manifest says ${MSHA[$p]}"; nbad=$((nbad+1)); fi
  done
  if [ "$nbad" = 0 ] && [ "${#MPATHS[@]}" -gt 0 ]; then pass "$b: all ${#MPATHS[@]} listed files' blobs at the import commit equal their manifest lines"; fi
done <<< "$REC_NAMES"

# ---- 3,4: tree versus manifests, record consistency ---------------------------------------------
ident=0; edited_ok=0; removed_ok=0; unrec=0
if [ "${#INMANIFEST[@]}" -gt 0 ]; then
  EXIST=()
  while IFS= read -r p; do [ -f "$ROOT/$p" ] && EXIST+=("$p"); done < <(printf '%s\n' "${!INMANIFEST[@]}" | sort)
  hash_tree_files() { local line; while IFS= read -r line; do TREESHA[${line:66}]="${line:0:64}"; done < <(cd "$ROOT" && sha256sum -- "$@" 2>/dev/null | tr -d '\r'); }
  [ "${#EXIST[@]}" -gt 0 ] && hash_tree_files "${EXIST[@]}"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    want="${MSHA[$p]}"; kind="${EDIT_KIND[$p]:-}"
    if [ -f "$ROOT/$p" ]; then
      cur="${TREESHA[$p]:-unreadable}"
      if [ "$cur" = "$want" ]; then
        ident=$((ident+1))
        if [ -n "$kind" ]; then fail "EDITED-AFTER-IMPORT: stale '$kind' entry for '$p' (the file equals the import; remove the entry)"; unrec=$((unrec+1)); fi
      else
        case "$kind" in
          edited)
            if [ "${EDIT_IMP[$p]}" != "$want" ]; then fail "EDITED-AFTER-IMPORT: '$p' records import sha256 ${EDIT_IMP[$p]} but the manifest says $want"; unrec=$((unrec+1))
            elif [ "${EDIT_CUR[$p]}" = "$cur" ]; then edited_ok=$((edited_ok+1))
            else fail "$p: tree sha256 $cur differs from the recorded edited sha256 ${EDIT_CUR[$p]} (a further, unrecorded change)"; unrec=$((unrec+1)); propose edited "$p" "$want" "$cur"; fi ;;
          removed) fail "EDITED-AFTER-IMPORT: '$p' is recorded as removed but the file exists"; unrec=$((unrec+1)) ;;
          *) fail "$p: differs from the import (tree sha256 $cur, manifest $want) and is not recorded in EDITED-AFTER-IMPORT-V1.tsv"; unrec=$((unrec+1)); propose edited "$p" "$want" "$cur" ;;
        esac
      fi
    else
      case "$kind" in
        removed)
          if [ "${EDIT_IMP[$p]}" = "$want" ]; then removed_ok=$((removed_ok+1))
          else fail "EDITED-AFTER-IMPORT: '$p' records import sha256 ${EDIT_IMP[$p]} but the manifest says $want"; unrec=$((unrec+1)); fi ;;
        *) fail "$p: listed by ${MSRC[$p]} but missing from the tree and not recorded as removed"; unrec=$((unrec+1)); propose removed "$p" "$want" "-" ;;
      esac
    fi
  done < <(printf '%s\n' "${!INMANIFEST[@]}" | sort)
fi
if [ "$unrec" = 0 ] && [ "$BADREC" = 0 ]; then
  pass "tree vs manifests: $NIMPORTED listed files = $ident identical + $edited_ok edited (recorded) + $removed_ok removed (recorded); 0 unrecorded differences"
else
  fail "tree vs manifests: $unrec unrecorded or inconsistent difference(s) among $NIMPORTED listed files ($ident identical, $edited_ok edited-recorded, $removed_ok removed-recorded), record problems: $BADREC"
fi
# record entries must name files that a manifest lists ('added' entries must name files that none lists)
stale=0
if [ "${#EDIT_KIND[@]}" -gt 0 ]; then
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    if [ "${EDIT_KIND[$p]}" = added ]; then
      if [ -n "${INMANIFEST[$p]:-}" ]; then fail "EDITED-AFTER-IMPORT: '$p' is recorded as added but a manifest lists it"; stale=$((stale+1)); fi
    else
      if [ -z "${INMANIFEST[$p]:-}" ]; then fail "EDITED-AFTER-IMPORT: '$p' is recorded as ${EDIT_KIND[$p]} but no import manifest lists it"; stale=$((stale+1)); fi
    fi
  done < <(printf '%s\n' "${!EDIT_KIND[@]}" | sort)
fi
if [ "$stale" = 0 ]; then pass "EDITED-AFTER-IMPORT-V1.tsv: ${#EDIT_KIND[@]} record(s), each names a manifest-listed file (or a recorded addition)"; fi

# ---- 5: new files and forbidden artifacts --------------------------------------------------------
list_files() { # dirs... -> repo-relative regular files (tracked or untracked-not-ignored in git mode)
  if [ "$MODE" = git ]; then
    { "${GIT[@]}" ls-files -- "$@"; "${GIT[@]}" ls-files -o --exclude-standard -- "$@"; } 2>/dev/null | sort -u \
      | while IFS= read -r f; do [ -f "$ROOT/$f" ] && printf '%s\n' "$f"; done
  else
    ( cd "$ROOT" && for d in "$@"; do [ -d "$d" ] && find "$d" -type f; done ) | sort -u
  fi
}
unlisted=0; nfiles=0; nadd=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  nfiles=$((nfiles+1))
  [ -n "${INMANIFEST[$f]:-}" ] && continue
  if [ "${EDIT_KIND[$f]:-}" = added ]; then
    cur="$(sha "$ROOT/$f")"
    if [ "${EDIT_CUR[$f]}" = "$cur" ]; then nadd=$((nadd+1))
    else fail "$f: recorded as added with sha256 ${EDIT_CUR[$f]} but the file is now $cur"; unlisted=$((unlisted+1)); propose added "$f" "-" "$cur"; fi
  else
    fail "$f: a file under an imported tree that is in no import manifest and is not recorded as 'added'"; unlisted=$((unlisted+1))
    propose added "$f" "-" "$(sha "$ROOT/$f")"
  fi
done < <(list_files desktop release-signer)
if [ "${#EDIT_KIND[@]}" -gt 0 ]; then
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    if [ "${EDIT_KIND[$p]}" = added ] && [ ! -f "$ROOT/$p" ]; then fail "EDITED-AFTER-IMPORT: '$p' is recorded as added but the file does not exist"; unlisted=$((unlisted+1)); fi
  done < <(printf '%s\n' "${!EDIT_KIND[@]}" | sort)
fi
if [ "$unlisted" = 0 ]; then pass "every file under desktop/ and release-signer/ is covered ($nfiles files: $((nfiles - nadd)) by an import manifest, $nadd by an 'added' record)"; fi
# Same patterns as .gitignore and build-package.sh: names are matched on the BASENAME (NODE-A-* starts a name, so
# the tracked qualification/read-node-a-tpm.ps1 helper is not evidence), target/ on the path, PRIVATE directly
# under qualification/ only.
forb=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  lf="${f,,}"; base="${lf##*/}"
  case "/$lf" in */target/*) fail "$f: build output (target/) in the tree"; forb=$((forb+1)); continue ;; esac
  case "$base" in
    *.sqlite|*.sqlite-*|*.sqlite3)
      fail "$f: private or generated evidence must never be in an imported, wallet or qualification tree"; forb=$((forb+1)); continue ;;
    *.wallet|*.dpapi|*.tpm-private|*.test-value-backup|node-a-*|*live-tpm*)
      fail "$f: private or generated evidence must never be in an imported, wallet or qualification tree"; forb=$((forb+1)); continue ;;
  esac
  case "$lf" in qualification/*private*) if [ "${lf#qualification/}" = "$base" ]; then fail "$f: PRIVATE evidence in qualification/"; forb=$((forb+1)); fi ;; esac
done < <(list_files desktop release-signer wallet-core qualification)
if [ "$forb" = 0 ]; then
  pass "no target/, *.sqlite*, *.wallet, *.dpapi, *.tpm-private, *.test-value-backup, NODE-A-*, *LIVE-TPM* or qualification/*PRIVATE* file in desktop/, release-signer/, wallet-core/ or qualification/"
fi

# A finished extracted package admits NO unlisted file anywhere. At build time
# the manifest is not written yet; build-package.sh repeats this after finalizing it.
if [ "$MODE" != git ] && [ -f "$ROOT/PACKAGE-MANIFEST.sha256" ]; then
  if perl "$ROOT/build/package-tree.pl" manifest "$ROOT"; then
    pass "whole package manifest identity including additions/removals"
  else fail "whole package manifest identity (unlisted/changed/missing files)"; fi
fi

# ---- 6: the imported public fixture's claims -----------------------------------------------------
FIX="qualification/release-policy-public-fixture-v1.json"
if [ -n "${INMANIFEST[$FIX]:-}" ] && [ -f "$ROOT/$FIX" ]; then
  t="$(tr -d '\r' < "$ROOT/$FIX")"
  if echo "$t" | grep -qE '"synthetic": *true' && echo "$t" | grep -qE '"production_authorized": *false'; then pass "$FIX: synthetic is true and production_authorized is false"
  else fail "$FIX: must say synthetic:true and production_authorized:false"; fi
  if echo "$t" | grep -iE '"[a-z0-9_]*(secret|private|seed|mnemonic|phrase|password|passphrase|token|credential)[a-z0-9_]*" *:' >/dev/null; then fail "$FIX: has a secret-named key"
  else pass "$FIX: no secret-named key (public descriptors, approvals, policy and manifest only)"; fi
fi

if [ "$PROPOSE" = 1 ] && [ -n "$PROPOSALS" ]; then
  echo "== Proposed EDITED-AFTER-IMPORT-V1.tsv lines (printed only; add them yourself with a real reason)"
  printf '%s' "$PROPOSALS"
fi
echo
echo "RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" = 0 ]
