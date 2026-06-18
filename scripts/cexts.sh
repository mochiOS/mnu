#!/usr/bin/env bash
set -euo pipefail

cext_manifest_value() {
    local key="$1"
    local file="$2"
    sed -n "s/^${key}[[:space:]]*=[[:space:]]*\"\(.*\)\"[[:space:]]*$/\1/p" "${file}" | head -n 1
}

cext_manifest_number() {
    local key="$1"
    local file="$2"
    sed -n "s/^${key}[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p" "${file}" | head -n 1
}

stage_module_cexts() {
    local root_dir="${ROOT_DIR:?ROOT_DIR is required}"
    local initfs_stage="${INITFS_STAGE:?INITFS_STAGE is required}"

    local modules_dir="${initfs_stage}/Modules"
    local manifest_file="${initfs_stage}/cexts.manifest"
    mkdir -p "${modules_dir}"
    : > "${manifest_file}"

    while IFS= read -r -d '' manifest; do
        local cext_dir
        cext_dir="$(dirname "${manifest}")"
        local name kind version artifact artifact_path staged_path digest

        name="$(cext_manifest_value "name" "${manifest}")"
        kind="$(cext_manifest_value "kind" "${manifest}")"
        version="$(cext_manifest_number "version" "${manifest}")"
        artifact="$(cext_manifest_value "artifact" "${manifest}")"

        if [[ -z "${name}" || -z "${kind}" || -z "${version}" ]]; then
            echo "fatal: invalid cext manifest: ${manifest}" >&2
            exit 1
        fi

        printf '%s|%s|%s|%s|%s\n' \
            "${name}" \
            "${kind}" \
            "${version}" \
            "${artifact}" \
            "${manifest}" >> "${manifest_file}"

        if [[ "${kind}" == "built-in" ]]; then
            continue
        fi

        if [[ "${kind}" != "module" ]]; then
            echo "fatal: unsupported cext kind '${kind}' in ${manifest}" >&2
            exit 1
        fi

        if [[ -z "${artifact}" ]]; then
            echo "fatal: module cext '${name}' is missing artifact path in ${manifest}" >&2
            exit 1
        fi

        artifact_path="${artifact}"
        if [[ "${artifact_path}" != /* ]]; then
            artifact_path="${cext_dir}/${artifact_path}"
        fi
        if [[ ! -f "${artifact_path}" ]]; then
            echo "fatal: module artifact not found: ${artifact_path}" >&2
            exit 1
        fi

        staged_path="${modules_dir}/${name}.cext"
        install -m 0644 "${artifact_path}" "${staged_path}"
        install -m 0644 "${manifest}" "${modules_dir}/${name}.toml"
    done < <(find "${root_dir}/examples/cexts" -mindepth 2 -maxdepth 2 -name cext.toml -print0)
}
