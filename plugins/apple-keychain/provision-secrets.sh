#!/usr/bin/env bash
# Compatibility entry point; all mapping, preflight and writes live in cli.py.
set -euo pipefail
plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${HERMES_PY:-${HERMES_PYTHON:-}}"
if [[ -z "$python_bin" ]]; then
  python_bin="$(command -v python3 || true)"
elif [[ "$python_bin" != */* ]]; then
  python_bin="$(command -v "$python_bin" || true)"
fi
if [[ -z "$python_bin" || ! -x "$python_bin" ]] || ! "$python_bin" -c 'import agent.secret_sources.base, hermes_cli.config' >/dev/null 2>&1; then
  echo "Cannot find a Python interpreter with Hermes installed; set HERMES_PY to the interpreter used by Hermes." >&2
  exit 1
fi
exec "$python_bin" "$plugin_dir/cli_standalone.py" "$@"
