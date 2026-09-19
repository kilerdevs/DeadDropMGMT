#!/bin/sh
# Build provenance for Settings → Version.
#
#   eval "$(tools/build_info.sh --export)" && docker compose up -d --build
#   tools/build_info.sh            # prints the JSON (for inspection)
#
# The Docker image has no .git (it is dockerignored on purpose), so the build
# host records what it is building: `git describe` against the v* release
# tags, the commit, the branch and the commit subject. The compose files pass
# it in as the DDMGMT_BUILD_INFO build arg (base64 of the JSON, so no quoting
# trouble); the Dockerfiles store it outside the docroot. Nothing here is
# secret, and it is shown to owners only.
set -eu
cd "$(dirname "$0")/.."

# JSON string body: control characters dropped, backslash and quote escaped.
js() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }

commit=$(git rev-parse HEAD 2>/dev/null || true)
describe=$(git describe --tags --match 'v[0-9]*' --long --always 2>/dev/null || true)
branch=$(git branch --show-current 2>/dev/null || true)
subject=$(git log -1 --format=%s 2>/dev/null || true)
dirty=false
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
    dirty=true
fi

json=$(printf '{"describe":"%s","commit":"%s","branch":"%s","subject":"%s","dirty":%s}' \
    "$(js "$describe")" "$(js "$commit")" "$(js "$branch")" "$(js "$subject")" "$dirty")

if [ "${1:-}" = "--export" ]; then
    printf 'export DDMGMT_BUILD_INFO=%s\n' "$(printf '%s' "$json" | base64 | tr -d '\n')"
else
    printf '%s\n' "$json"
fi
