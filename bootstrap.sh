#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Southland Labs
set -euo pipefail

main() {
    local stage_only=false
    case "${1:-}" in
        '') ;;
        --stage-only) stage_only=true ;;
        --help|-h)
            printf '%s\n' 'Install Proxmox Makeover 0.1-beta on PVE 9.' \
                'Run as root over SSH. Close Proxmox consoles and wait for tasks first.' \
                'Use --stage-only to download and prepare without activating.'
            return ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; return 2 ;;
    esac
    if (( $# > 1 )); then
        printf '%s\n' 'Only --stage-only or --help is accepted.' >&2
        return 2
    fi
    if (( EUID != 0 )); then
        printf '%s\n' 'Run this installer as root on the Proxmox host.' >&2
        return 1
    fi
    local command
    for command in curl sha256sum mktemp tar python3 dpkg-query apt-get; do
        command -v "$command" >/dev/null || {
            printf 'Required host command is missing: %s\n' "$command" >&2
            return 1
        }
    done
    local pve_version
    pve_version=$(dpkg-query -W -f='${Version}' pve-manager 2>/dev/null) || {
        printf '%s\n' 'This installer must run on a Proxmox VE host.' >&2
        return 1
    }
    [[ "$pve_version" == 9.* ]] || {
        printf 'This beta requires Proxmox VE 9; found %s.\n' "$pve_version" >&2
        return 1
    }

    umask 077
    local work_dir
    work_dir=$(mktemp -d /tmp/proxmox-makeover.XXXXXXXX)
    # Expand the generated private path now; the trap outlives main's locals.
    trap "rm -rf -- '$work_dir'" EXIT
    local archive=proxmox-makeover-0.1-beta.tar.gz
    local release=https://github.com/vipgabe09267/SLL_Proxmox_Makeover/releases/download/v0.1-beta
    local -a fetch=(curl --fail --silent --show-error --location --proto '=https'
        --proto-redir '=https' --tlsv1.2 --retry 2 --connect-timeout 10 --max-time 180)
    printf '%s\n' 'Downloading Proxmox Makeover 0.1-beta...'
    "${fetch[@]}" --max-filesize 16777216 "$release/$archive" -o "$work_dir/$archive"
    "${fetch[@]}" --max-filesize 4096 "$release/SHA256SUMS" -o "$work_dir/SHA256SUMS"
    local checksum expected_hash expected_archive extra
    checksum=$(< "$work_dir/SHA256SUMS")
    [[ "$checksum" != *$'\n'* ]] || {
        printf '%s\n' 'Invalid release checksum file.' >&2; return 1
    }
    read -r expected_hash expected_archive extra <<< "$checksum"
    [[ "$expected_hash" =~ ^[0-9a-f]{64}$ && "$expected_archive" == "$archive" && -z "$extra" ]] || {
        printf '%s\n' 'Invalid release checksum file.' >&2; return 1
    }
    (cd "$work_dir" && sha256sum --check --strict SHA256SUMS)

    # Extract only bounded regular files under the expected source directory.
    python3 -I - "$work_dir/$archive" "$work_dir" <<'PY'
import pathlib
import shutil
import sys
import tarfile

destination = pathlib.Path(sys.argv[2])
with tarfile.open(sys.argv[1], 'r:gz') as package:
    members = package.getmembers()
    names = [member.name for member in members]
    if not members or len(members) > 512 or len(set(names)) != len(names):
        raise SystemExit('Invalid release archive file list.')
    if sum(member.size for member in members) > 64 * 1024 * 1024:
        raise SystemExit('Release archive exceeds the extraction limit.')
    for member in members:
        name = pathlib.PurePosixPath(member.name)
        if (not member.isfile() or name.is_absolute() or '..' in name.parts
                or len(name.parts) < 2 or name.parts[0] != 'proxmox-makeover'):
            raise SystemExit('Unsafe release archive entry.')
    for member in members:
        target = destination.joinpath(*pathlib.PurePosixPath(member.name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with package.extractfile(member) as source, target.open('xb') as output:
            shutil.copyfileobj(source, output)
        target.chmod(0o755 if member.mode & 0o111 else 0o644)
PY
    local source="$work_dir/proxmox-makeover"
    if [[ "$stage_only" == false ]]; then
        python3 "$source/scripts/lifecycle.py" session-check
    fi

    local package state
    local -a missing=()
    for package in python3 python3-pil python3-fido2 python3-cryptography perl \
        liburi-perl libwww-perl libio-compress-perl; do
        state=$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null) || state=''
        [[ "$state" == installed ]] || missing+=("$package")
    done
    if (( ${#missing[@]} )); then
        printf 'Installing missing prerequisites: %s\n' "${missing[*]}"
        apt-get update -o APT::Update::Error-Mode=any
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-upgrade -- "${missing[@]}"
    fi

    # Stage a retained local copy, so recovery never depends on this temp tree.
    bash "$source/install.sh"
    if [[ "$stage_only" == false ]]; then
        python3 "$source/scripts/lifecycle.py" activate
        printf '%s\n' 'Installed. Refresh Proxmox and open Proxmox Makeover in the header.'
    fi
}

main "$@"
