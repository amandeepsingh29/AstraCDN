#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-${ROOT_DIR}/db/migrations}"

POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-astracdn}"
POSTGRES_USER="${POSTGRES_USER:-astracdn}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-astracdn_local_password}"
DB_SSLMODE="${DB_SSLMODE:-disable}"

PSQL_BIN="${PSQL_BIN:-psql}"
PODMAN_BIN="${PODMAN_BIN:-podman}"
PSQL_CONTAINER="${PSQL_CONTAINER:-}"
DATABASE_URL="${DATABASE_URL:-}"

usage() {
    cat <<'USAGE'
Usage:
  scripts/db-migrate.sh [up|status|validate]

Commands:
  up        Apply pending migrations in db/migrations. This is the default.
  status    Print applied and pending migration status.
  validate  Check migration filenames and previously applied checksums.

Connection env:
  DATABASE_URL       Full Postgres URL. Overrides POSTGRES_* fields when set.
  POSTGRES_HOST      Hostname for psql. Default: localhost.
  POSTGRES_PORT      Port for psql. Default: 5432.
  POSTGRES_DB        Database name. Default: astracdn.
  POSTGRES_USER      Database user. Default: astracdn.
  POSTGRES_PASSWORD  Password passed through PGPASSWORD.
  DB_SSLMODE         sslmode when DATABASE_URL is not set. Default: disable.

Podman-friendly env:
  PSQL_CONTAINER     If set, run psql with: podman exec -i "$PSQL_CONTAINER" psql ...
  PODMAN_BIN         Podman executable. Default: podman.
  PSQL_BIN           psql executable name/path. Default: psql.
  MIGRATIONS_DIR     Migration directory. Default: db/migrations.
USAGE
}

psql_conninfo() {
    if [[ -n "${DATABASE_URL}" ]]; then
        printf '%s\n' "${DATABASE_URL}"
        return
    fi

    printf 'host=%s port=%s dbname=%s user=%s sslmode=%s\n' \
        "${POSTGRES_HOST}" \
        "${POSTGRES_PORT}" \
        "${POSTGRES_DB}" \
        "${POSTGRES_USER}" \
        "${DB_SSLMODE}"
}

run_psql() {
    local common_args=(-X -v ON_ERROR_STOP=1)

    if [[ -n "${PSQL_CONTAINER}" ]]; then
        PGPASSWORD="${POSTGRES_PASSWORD}" "${PODMAN_BIN}" exec -i \
            -e PGPASSWORD="${POSTGRES_PASSWORD}" \
            "${PSQL_CONTAINER}" \
            "${PSQL_BIN}" "${common_args[@]}" "$@" "$(psql_conninfo)"
        return
    fi

    PGPASSWORD="${POSTGRES_PASSWORD}" "${PSQL_BIN}" "${common_args[@]}" "$@" "$(psql_conninfo)"
}

query_scalar() {
    run_psql -Atqc "$1"
}

hash_file() {
    local file="$1"

    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${file}" | awk '{print $1}'
        return
    fi

    sha256sum "${file}" | awk '{print $1}'
}

ensure_ledger() {
    run_psql <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
SQL
}

migration_files() {
    find "${MIGRATIONS_DIR}" -maxdepth 1 -type f -name '*.sql' | sort
}

parse_migration() {
    local file="$1"
    local base
    base="$(basename "${file}")"

    if [[ ! "${base}" =~ ^([0-9]{3,})_([A-Za-z0-9_.-]+)\.sql$ ]]; then
        echo "invalid migration filename: ${base}" >&2
        echo "expected format: NNN_description.sql" >&2
        exit 1
    fi

    MIGRATION_VERSION="${BASH_REMATCH[1]}"
    MIGRATION_DESCRIPTION="${BASH_REMATCH[2]}"
}

validate_migrations() {
    ensure_ledger

    local file version description checksum applied_checksum
    while IFS= read -r file; do
        [[ -n "${file}" ]] || continue
        parse_migration "${file}"
        version="${MIGRATION_VERSION}"
        description="${MIGRATION_DESCRIPTION}"
        checksum="$(hash_file "${file}")"
        applied_checksum="$(query_scalar "SELECT checksum FROM schema_migrations WHERE version = '${version}';")"

        if [[ -n "${applied_checksum}" && "${applied_checksum}" != "${checksum}" ]]; then
            echo "checksum mismatch for migration ${version}_${description}.sql" >&2
            echo "applied: ${applied_checksum}" >&2
            echo "current: ${checksum}" >&2
            exit 1
        fi
    done < <(migration_files)
}

apply_migration() {
    local file="$1"
    local version="$2"
    local description="$3"
    local checksum="$4"
    local tmp

    tmp="$(mktemp)"
    trap 'rm -f "${tmp}"' RETURN

    {
        echo "BEGIN;"
        cat "${file}"
        echo
        echo "INSERT INTO schema_migrations (version, description, checksum)"
        echo "VALUES ('${version}', '${description}', '${checksum}');"
        echo "COMMIT;"
    } > "${tmp}"

    run_psql -f "${tmp}"
}

status_migrations() {
    ensure_ledger

    local file version description checksum applied_at state
    while IFS= read -r file; do
        [[ -n "${file}" ]] || continue
        parse_migration "${file}"
        version="${MIGRATION_VERSION}"
        description="${MIGRATION_DESCRIPTION}"
        checksum="$(hash_file "${file}")"
        applied_at="$(query_scalar "SELECT applied_at FROM schema_migrations WHERE version = '${version}' AND checksum = '${checksum}';")"
        if [[ -n "${applied_at}" ]]; then
            state="applied"
        else
            state="pending"
        fi
        printf '%s_%s.sql %s' "${version}" "${description}" "${state}"
        if [[ -n "${applied_at}" ]]; then
            printf ' %s' "${applied_at}"
        fi
        printf '\n'
    done < <(migration_files)
}

apply_pending() {
    ensure_ledger
    validate_migrations

    local file version description checksum applied_checksum
    while IFS= read -r file; do
        [[ -n "${file}" ]] || continue
        parse_migration "${file}"
        version="${MIGRATION_VERSION}"
        description="${MIGRATION_DESCRIPTION}"
        checksum="$(hash_file "${file}")"
        applied_checksum="$(query_scalar "SELECT checksum FROM schema_migrations WHERE version = '${version}';")"

        if [[ -n "${applied_checksum}" ]]; then
            echo "skip ${version}_${description}.sql"
            continue
        fi

        echo "apply ${version}_${description}.sql"
        apply_migration "${file}" "${version}" "${description}" "${checksum}"
    done < <(migration_files)
}

command="${1:-up}"

case "${command}" in
    up)
        apply_pending
        ;;
    status)
        validate_migrations
        status_migrations
        ;;
    validate)
        validate_migrations
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
