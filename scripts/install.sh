#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/install.sh --project /path/to/project [--force] [--dry-run]
  bash scripts/install.sh --global [--force] [--dry-run]

Options:
  --project PATH   Install into PATH/.claude
  --global         Install into ~/.claude
  --force          Replace existing SecureScan files if they differ
  --dry-run        Print actions without writing files
  --help           Show this help
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_PATH=""
GLOBAL_INSTALL=0
FORCE=0
DRY_RUN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --project)
      [ "$#" -ge 2 ] || { echo "Missing value for --project" >&2; exit 2; }
      PROJECT_PATH="$2"
      shift 2
      ;;
    --global)
      GLOBAL_INSTALL=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ "$GLOBAL_INSTALL" -eq 1 ] && [ -n "$PROJECT_PATH" ]; then
  echo "Choose either --global or --project, not both." >&2
  exit 2
fi

if [ "$GLOBAL_INSTALL" -eq 0 ] && [ -z "$PROJECT_PATH" ]; then
  usage >&2
  exit 2
fi

if [ "$GLOBAL_INSTALL" -eq 1 ]; then
  CLAUDE_ROOT="${HOME}/.claude"
else
  CLAUDE_ROOT="${PROJECT_PATH%/}/.claude"
fi

AGENT_DEST="${CLAUDE_ROOT}/agents"
SKILL_DEST="${CLAUDE_ROOT}/skills"

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRY-RUN:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

copy_file() {
  local src="$1"
  local dest="$2"

  if [ -f "$dest" ]; then
    if cmp -s "$src" "$dest"; then
      echo "unchanged: $dest"
      return
    fi
    if [ "$FORCE" -ne 1 ]; then
      echo "Refusing to overwrite different file: $dest (use --force)" >&2
      exit 1
    fi
  fi

  run mkdir -p "$(dirname "$dest")"
  run cp "$src" "$dest"
  echo "installed: $dest"
}

copy_dir() {
  local src="$1"
  local dest="$2"

  if [ -d "$dest" ]; then
    if diff -qr "$src" "$dest" >/dev/null 2>&1; then
      echo "unchanged: $dest"
      return
    fi
    if [ "$FORCE" -ne 1 ]; then
      echo "Refusing to overwrite different directory: $dest (use --force)" >&2
      exit 1
    fi
  fi

  run mkdir -p "$dest"
  run cp -R "${src}/." "$dest/"
  echo "installed: $dest"
}

bash "${ROOT_DIR}/scripts/validate-package.sh" "${ROOT_DIR}"

run mkdir -p "$AGENT_DEST" "$SKILL_DEST"

for agent in "${ROOT_DIR}"/agents/securescan*.md; do
  copy_file "$agent" "${AGENT_DEST}/$(basename "$agent")"
done

for skill in "${ROOT_DIR}"/skills/*; do
  [ -d "$skill" ] || continue
  copy_dir "$skill" "${SKILL_DEST}/$(basename "$skill")"
done

if [ "$DRY_RUN" -eq 1 ]; then
  echo "SecureScan dry run completed for ${CLAUDE_ROOT}"
else
  echo "SecureScan installed into ${CLAUDE_ROOT}"
  echo "Restart Claude Code or reload the project if agents are not immediately visible."
fi
