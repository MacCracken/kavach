#!/usr/bin/env bash
# Version bump for kavach (Cyrius-native).
#
# Updates the two version sources that actually exist in this repo:
#   1. VERSION              — single source of truth
#   2. CHANGELOG.md         — inserts a dated section after [Unreleased]
#
# Notes:
#   - cyrius.cyml reads the version via `version = "${file:VERSION}"`, so it
#     needs no edit.
#   - kavach has NO embedded "kavach X.Y.Z" source literal (nothing to keep in
#     sync, no CI version-drift check) and ships NO dist bundle (binary / src-
#     consumed), so there is no version_str.cyr or `cyrius distlib` step.
#   - Git is the user's: this script touches files only, never runs git.
#
# (Replaced the Rust-era script that bumped VERSION + Cargo.toml; kavach has no
#  Cargo.toml since the Cyrius port, so the old script died mid-run.)
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <new-version>"
    echo "Current: $(cat "$(dirname "${BASH_SOURCE[0]}")/../VERSION" 2>/dev/null || echo '?')"
    exit 1
fi

NEW="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OLD="$(tr -d '[:space:]' < "$ROOT/VERSION")"

echo "$NEW" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.]+)?$' || {
    echo "error: '$NEW' is not valid semver" >&2
    exit 1
}

if [ "$NEW" = "$OLD" ]; then
    echo "Already at $OLD"
    exit 0
fi

echo "Bumping kavach $OLD -> $NEW"

# 1. VERSION
echo "$NEW" > "$ROOT/VERSION"
echo "  Updated VERSION"

# 2. CHANGELOG.md — insert a dated section right after [Unreleased] (idempotent).
#    Existing [Unreleased] bullets fall under the new version section; a fresh
#    empty [Unreleased] stays on top.
if [ -f "$ROOT/CHANGELOG.md" ]; then
    if grep -q "## \[$NEW\]" "$ROOT/CHANGELOG.md"; then
        echo "  CHANGELOG.md already has [$NEW] — left as-is"
    else
        sed -i "/## \[Unreleased\]/a\\
\\
## [$NEW] — $(date +%Y-%m-%d)" "$ROOT/CHANGELOG.md"
        echo "  Updated CHANGELOG.md"
    fi
fi

echo ""
echo "Done. The user owns git:"
echo "  git add -A && git commit -m \"bump to $NEW\" && git tag $NEW"
