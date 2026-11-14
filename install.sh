#!/usr/bin/env bash
set -euo pipefail
project_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -x /usr/bin/python3 ]] || {
  echo 'Python 3 is required. Install dependencies first: apt install python3 python3-pil python3-fido2 python3-cryptography' >&2
  exit 1
}
exec /usr/bin/python3 "$project_dir/scripts/lifecycle.py" install --source "$project_dir" "$@"
