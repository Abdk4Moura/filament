#!/usr/bin/env bash
# rbuild: build the filament CLI on GitHub Actions and download the binary.
#
# Dispatches .github/workflows/build-remote.yml for a ref, waits for it, and
# pulls the artifact down. Free on this public repo, so this is the default
# way to get a binary without compiling on a small box. Needs `gh` logged in
# with the `repo` + `workflow` scopes and `jq`.
#
#   scripts/rbuild.sh                          # current branch, musl release
#   scripts/rbuild.sh --ref main --target x86_64-unknown-linux-gnu
#   scripts/rbuild.sh --profile dev --test
#   scripts/rbuild.sh --features "--features static" -- --locked
#   scripts/rbuild.sh --out ~/.local/bin      # drop the binary straight there
#
# The ref must already be pushed: Actions builds what is on GitHub, not your
# working tree. Uncommitted or unpushed work is reported and the build refuses
# unless --force is given.

set -euo pipefail

REPO="${RBUILD_REPO:-}"                        # owner/name; auto-detected from origin
WORKFLOW="build-remote.yml"
REF=""
TARGET="${RBUILD_TARGET:-x86_64-unknown-linux-musl}"
PROFILE="release"
FEATURES=""
RUN_TESTS=false
RETENTION="7"
OUT="${RBUILD_OUT:-./out/rbuild}"
DOWNLOAD=true
FORCE=false
EXTRA=()

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --ref)       REF="$2"; shift 2 ;;
    --target)    TARGET="$2"; shift 2 ;;
    --profile)   PROFILE="$2"; shift 2 ;;
    --features)  FEATURES="$2"; shift 2 ;;
    --test)      RUN_TESTS=true; shift ;;
    --retention) RETENTION="$2"; shift 2 ;;
    --out)       OUT="$2"; shift 2 ;;
    --no-download) DOWNLOAD=false; shift ;;
    --force)     FORCE=true; shift ;;
    -h|--help)   usage 0 ;;
    --)          shift; EXTRA=("$@"); break ;;
    *)           echo "rbuild: unknown argument: $1" >&2; usage 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "rbuild: missing $1" >&2; exit 2; }; }
need gh; need jq; need git

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

if [ -z "$REPO" ]; then
  REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)"
  [ -n "$REPO" ] || { echo "rbuild: cannot detect repo; set RBUILD_REPO=owner/name" >&2; exit 2; }
fi
[ -n "$REF" ] || REF="$(git rev-parse --abbrev-ref HEAD)"

# Refuse to build a ref that does not match what GitHub has, unless forced.
if [ "$FORCE" = false ] && [ "$REF" = "$(git rev-parse --abbrev-ref HEAD)" ]; then
  dirty="$(git status --porcelain --untracked-files=no | wc -l)"
  git fetch -q origin "$REF" 2>/dev/null || true
  local_sha="$(git rev-parse HEAD)"
  remote_sha="$(git rev-parse "origin/$REF" 2>/dev/null || echo none)"
  if [ "$dirty" != "0" ]; then
    echo "rbuild: $dirty tracked file(s) modified locally; the remote build will not include them." >&2
    echo "        Commit and push, or pass --force to build origin/$REF as-is." >&2
    exit 3
  fi
  if [ "$local_sha" != "$remote_sha" ]; then
    echo "rbuild: local $REF is $local_sha but origin/$REF is $remote_sha." >&2
    echo "        Push first, or pass --force to build what origin has." >&2
    exit 3
  fi
fi

TAG="$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
t0=$(date +%s)

echo "rbuild: dispatching $WORKFLOW on $REPO@$REF  target=$TARGET profile=$PROFILE tag=$TAG"
gh workflow run "$WORKFLOW" -R "$REPO" --ref "$REF" \
  -f "tag=$TAG" -f "target=$TARGET" -f "profile=$PROFILE" \
  -f "features=$FEATURES" -f "cargo_args=${EXTRA[*]:-}" \
  -f "run_tests=$RUN_TESTS" -f "retention_days=$RETENTION"

# Find our run by tag. The run appears a few seconds after dispatch.
RUN_ID=""
for _ in $(seq 1 30); do
  RUN_ID="$(gh run list -R "$REPO" --workflow "$WORKFLOW" --event workflow_dispatch \
              --json databaseId,displayTitle --limit 20 \
              --jq ".[] | select(.displayTitle | contains(\"$TAG\")) | .databaseId" | head -1)"
  [ -n "$RUN_ID" ] && break
  sleep 2
done
[ -n "$RUN_ID" ] || { echo "rbuild: dispatched but could not find run with tag $TAG" >&2; exit 4; }
URL="https://github.com/$REPO/actions/runs/$RUN_ID"
echo "rbuild: run $RUN_ID  $URL"

set +e
gh run watch "$RUN_ID" -R "$REPO" --exit-status --interval 5 >/dev/null
status=$?
set -e
t1=$(date +%s)

# Timing breakdown from the job's step timestamps.
gh run view "$RUN_ID" -R "$REPO" --json jobs,conclusion,createdAt,startedAt --jq '
  .jobs[0] as $j |
  "rbuild: conclusion=\(.conclusion)  queue=\(( ($j.startedAt|fromdateiso8601) - (.createdAt|fromdateiso8601) ))s  job=\(( ($j.completedAt|fromdateiso8601) - ($j.startedAt|fromdateiso8601) ))s",
  ($j.steps[] | select(.name == "Build" or .name == "Test" or .name == "Run sccache" or .name == "Cache cargo registry")
     | "rbuild:   step \(.name): \(( (.completedAt|fromdateiso8601) - (.startedAt|fromdateiso8601) ))s (\(.conclusion))")
' 2>/dev/null || true
echo "rbuild: wall=$((t1 - t0))s (dispatch to finish)"

if [ "$status" -ne 0 ]; then
  echo "rbuild: FAILED, last log lines:" >&2
  gh run view "$RUN_ID" -R "$REPO" --log-failed 2>/dev/null | tail -40 >&2 || true
  exit "$status"
fi

if [ "$DOWNLOAD" = true ]; then
  ART="filament-$TARGET-$PROFILE"
  mkdir -p "$OUT"
  tmp="$(mktemp -d)"
  gh run download "$RUN_ID" -R "$REPO" -n "$ART" -D "$tmp"
  install -m 0755 "$tmp/filament" "$OUT/filament"
  cp "$tmp/BUILD_INFO" "$OUT/BUILD_INFO"
  rm -rf "$tmp"
  echo "rbuild: binary -> $OUT/filament"
  sed 's/^/rbuild:   /' "$OUT/BUILD_INFO"
fi
