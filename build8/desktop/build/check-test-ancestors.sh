#!/usr/bin/env bash
# Production-equivalent ancestor rule: root/effective-user owner; no group/other write.
# Checks existing ancestors; never repairs/chmods someone else's paths.
check_ancestors() {
  local path=$1 purpose=$2 report=$3 uid mode owner bits bad=0
  uid=$(id -u)
  case "$path" in /*) ;; *) echo "ABORT: $purpose must be absolute: $path" >&2; return 1 ;; esac
  while :; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      if [ -L "$path" ] || [ ! -d "$path" ]; then
        echo "ABORT: $purpose ancestor is a link or non-directory: $path" >&2; return 1
      fi
      mode=$(stat -c '%a' -- "$path") || return 1
      owner=$(stat -c '%u' -- "$path") || return 1
      printf '%s path=%s mode=%s owner=%s effective_uid=%s\n' "$purpose" "$path" "$mode" "$owner" "$uid" >> "$report"
      bits=$((8#$mode))
      if [ "$owner" != 0 ] && [ "$owner" != "$uid" ] || [ $((bits & 8#022)) != 0 ]; then
        echo "ABORT: unsafe $purpose ancestor $path mode=$mode owner=$owner; use a new private workspace below root/user-owned ancestors without group/other write; do not chmod unrelated directories" >&2
        bad=1; break
      fi
    fi
    [ "$path" = / ] && break
    path=$(dirname -- "$path")
  done
  [ "$bad" = 0 ]
}
