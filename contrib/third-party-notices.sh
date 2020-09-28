#!/bin/bash

set -euo pipefail

# This script identifies all the third-party dependencies of the crates in the workspace.
# At a high level, `cargo metadata --format-version 1` gives this information in JSON.

case "$ARCH" in
    'amd64')
        platform='x86_64-unknown-linux-gnu'
        ;;

    'arm32v7')
        platform='armv7-unknown-linux-gnueabihf'
        ;;

    'aarch64')
        platform='aarch64-unknown-linux-gnu'
        ;;

    *)
        exit 1
        ;;
esac

cargo_metadata="$(
    cargo metadata --format-version 1 --filter-platform "$platform" |
        jq -r '.resolve.nodes'
)"

# These dependencies include more than we ship, because they include dependencies of crates like iotedged and pkcs11-test.
# So, for each shipping crate, we enumerate only their dependencies, the dependencies of their dependencies, and so on,
# and build up the final list of dependencies.

# Map of package ID to 0 or 1. 0 => not yet processed, 1 => processed
declare -A dependencies

for crate_name in 'aziot-certd' 'aziot-identityd' 'aziot-keyd' 'aziot-keys'; do
    crate_pkg_id="$(
        <<< "$cargo_metadata" jq -r \
            --arg 'crate_name' "$crate_name" \
            '
                map(select(.id | startswith("\($crate_name) "))) |
                first |
                .id
            '
    )"
    dependencies[$crate_pkg_id]=0
done

while :; do
    previous_dependencies_len="${#dependencies[@]}"

    declare -A new_dependencies

    for crate_pkg_id in "${!dependencies[@]}"; do
        if [ "${dependencies[$crate_pkg_id]}" = '0' ]; then
            new_dependencies[$crate_pkg_id]=1
            while read -r dep_pkg_id; do
                new_dependencies[$dep_pkg_id]=0
            done < <(<<< "$cargo_metadata" \
                jq -r --arg crate_pkg_id "$crate_pkg_id" '
                    map(
                        select(.id == $crate_pkg_id) |
                        .deps[] |
                        select((.dep_kinds | any(.kind == null or .kind == "build"))) |
                        .pkg
                    ) |
                    unique[]
                '
            )
        fi
    done

    for crate_name in "${!new_dependencies[@]}"; do
        dependencies[$crate_name]="${new_dependencies[$crate_name]}"
    done

    new_dependencies_len="${#dependencies[@]}"
    if (( new_dependencies_len == previous_dependencies_len )); then
        echo "Done. Found $new_dependencies_len dependencies." >&2
        break
    else
        echo "Found $(( new_dependencies_len - previous_dependencies_len )) new dependencies..." >&2
    fi
done

dependencies_array="$(
    printf '%s\n' "${!dependencies[@]}" |
        jq -Rc '[., inputs]'
)"

cat <<-EOF
Azure IoT Identity Service and related services


Third Party Notices

This file is based on or incorporates material from the projects listed below
(Third Party IP). The original copyright notice and the license under which
Microsoft received such Third Party IP, are set forth below.
Such licenses and notices are provided for informational purposes only.
Unless otherwise specified, Microsoft licenses the Third Party IP to you
under the licensing terms for the Microsoft product. Microsoft reserves
all other rights not expressly granted under this agreement,
whether by implication, estoppel or otherwise.
EOF

cargo metadata --format-version 1 |
    jq -r --argjson 'dependencies' "$dependencies_array" '
        [
            .packages[] |
            select(.source != null) |
            select(.id as $pkg_id | ($dependencies | index($pkg_id)) != null) |
            { id, license, manifest_path, repository }
        ] |
        sort_by(.id)[] |
        (.id | scan("^[^ ]+ [^ ]+")) as $name |
        .license as $license |
        {
            id,
            license: (
                if $license == null then
                    error("crate \($name) has null license")
                elif (
                    ($license == "MIT") or
                    ($license | startswith("MIT/")) or
                    ($license | startswith("MIT /")) or
                    ($license | startswith("MIT OR")) or
                    ($license | endswith("/MIT")) or
                    ($license | endswith("/ MIT")) or
                    ($license | endswith("OR MIT")) or
                    ($license | contains("/MIT/")) or
                    ($license | contains("/ MIT /")) or
                    ($license | contains("OR MIT OR")) or
                    false
                ) then
                    "MIT"
                elif (
                    ($license == "Apache-2.0") or
                    ($license | startswith("Apache-2.0 OR")) or
                    false
                ) then
                    "Apache-2.0"
                elif $license == "BSD-3-Clause" then
                    "BSD-3-Clause"
                elif $license == "Zlib" then
                    "Zlib"
                else
                    error("crate \($name) has unknown license \($license)")
                end
            ),
            manifest_path,
            repository: (if .repository == null then "unknown repository" else .repository end),
        } |
        "\(.id)|\(.license)|\(.manifest_path)|\(.repository)"
    ' |
    while read -r line; do
        <<< "$line" IFS='|' read -r id license manifest_path repository
        <<< "$id" IFS=' ' read -r name version rest

        crate_directory="$(dirname "$manifest_path")"

        case "$license" in
            'MIT')
                license_file_suffix='MIT'
                ;;

            'Apache-2.0')
                license_file_suffix='APACHE'
                ;;

            'BSD-3-Clause')
                license_file_suffix='BSD'
                ;;

            'Zlib')
                license_file_suffix='ZLIB'
                ;;

            *)
                exit 1
                ;;
        esac

        license_file="$(find "$crate_directory" -maxdepth 1 -type f -regextype posix-egrep -regex ".*/LICEN[CS]E-$license_file_suffix(\\.(md|txt))?" | head -n1)"
        if [ -z "$license_file" ]; then
            license_file="$(find "$crate_directory" -maxdepth 1 -type f -regextype posix-egrep -regex '.*/LICEN[CS]E(\.(md|txt))?' | head -n1)"
        fi
        if [ -z "$license_file" ]; then
            echo "$name:$version at $manifest_path has license $license but its license file could not be found" >&2
            exit 1
        fi

        printf '\n\n***\n\n%s %s ( %s ) - %s\n\n%s' "$name" "$version" "$repository" "$license" "$(cat "$license_file")"
    done
