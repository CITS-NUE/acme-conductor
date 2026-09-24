#!/usr/bin/env bash
# release-guard.sh: refuse to release from a commit that is not on main.
#
# A release is a version tag on main (CONTRIBUTING.md, docs/adr/0017). The
# release workflow calls this before publishing anything; the dispatch-only
# workflow .github/workflows/release-guard-check.yml calls it with any ref
# so the rule can be exercised, both ways, without a tag and without a
# publish. Needs a clone with full history and the base branch fetchable
# from origin.
#
#   scripts/release-guard.sh <ref>          # refs/tags/v1.2.3, a branch, a SHA
#   RELEASE_BASE_BRANCH=main (default)
set -euo pipefail

ref="${1:?usage: release-guard.sh <ref>}"
base="${RELEASE_BASE_BRANCH:-main}"

git fetch --quiet --no-tags origin "$base"

# Resolve the ref to a commit: an annotated tag is dereferenced, and a bare
# branch name that only exists on origin is tried there too.
if ! commit="$(git rev-parse --verify --quiet "${ref}^{commit}")"; then
  if ! commit="$(git rev-parse --verify --quiet "origin/${ref}^{commit}")"; then
    echo "::error::${ref} does not resolve to a commit" >&2
    exit 2
  fi
fi

if git merge-base --is-ancestor "$commit" "origin/${base}"; then
  echo "ok: ${ref} -> ${commit} is in origin/${base}'s history"
else
  echo "::error::${ref} points at ${commit}, which is not in origin/${base}'s history; a release is a version tag on ${base}" >&2
  exit 1
fi
