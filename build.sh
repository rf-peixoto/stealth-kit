#!/usr/bin/env bash
# build.sh — build the envcheck examples (and, optionally, obfuscated builds).
#
#   ./build.sh                 Build the examples normally        -> build/
#   ./build.sh --obfuscate     Run the string obfuscator on every
#                              C source first, then compile them   -> build/*.obf
#   ./build.sh --obfuscate --seed 1234   Reproducible obfuscation
#   ./build.sh clean           Remove the build/ directory
#   ./build.sh --help
#
# Environment overrides:  CC, CFLAGS, PYTHON
#
# On Windows use MSVC directly (the obfuscator is plain Python and works there
# too; see README). Example:  cl /O2 /Iinclude examples\report.c src\envcheck.c
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2 -Wall -Wextra}"
PYTHON="${PYTHON:-python3}"

INC="-I${ROOT}/include"
LIB_SRC="${ROOT}/src/envcheck.c"
BUILD="${ROOT}/build"
OBF_DIR="${BUILD}/obf"                     # obfuscated sources land here
EXAMPLES=(example report guard)            # examples/<name>.c  (link the library)
OBF="${PYTHON} ${ROOT}/tools/cobfuscate.py"

# Extra flags needed only for obfuscated builds: an obfuscated literal used as a
# printf format is no longer a string literal (so -Wformat-security fires), and
# some deob functions / blobs go unused per translation unit.
# (obfuscated sources are machine-generated: per-string buffers/blobs for code
#  inside inactive #if branches look unused, and unused deob variants appear.)
OBF_CFLAGS="-Wno-format-security -Wno-unused-function -Wno-unused-const-variable -Wno-unused-variable"

usage() {
    sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

OBFUSCATE=0
SEED_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        clean)              rm -rf "${BUILD}"; echo "cleaned ${BUILD}"; exit 0 ;;
        --obfuscate|-O)     OBFUSCATE=1 ;;
        --seed)             SEED_ARGS=(--seed "$2"); shift ;;
        --seed=*)           SEED_ARGS=(--seed "${1#*=}") ;;
        -h|--help)          usage ;;
        *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

mkdir -p "${BUILD}"

# ---------------------------------------------------------------------------
# Plain build
# ---------------------------------------------------------------------------
if [ "${OBFUSCATE}" -eq 0 ]; then
    for n in "${EXAMPLES[@]}"; do
        echo "CC   ${n}"
        # shellcheck disable=SC2086
        "${CC}" ${CFLAGS} ${INC} "${ROOT}/examples/${n}.c" "${LIB_SRC}" -o "${BUILD}/${n}"
    done
    echo "CC   demo"
    # shellcheck disable=SC2086
    "${CC}" ${CFLAGS} "${ROOT}/demo/demo.c" -o "${BUILD}/demo"

    echo
    echo "Built -> ${BUILD}/"
    echo "  ./build/report   [--json] [--no-ptrace] [--no-backdoor] [--sleep-skew]"
    echo "  GUARD_DRY_RUN=1 ./build/guard     # test the enforcement example safely"
    echo "  ./build/example  # JSON report"
    echo "  ./build/demo     # the obfuscator's sample program (plain)"
    echo
    echo "Run ./build.sh --obfuscate to produce string-obfuscated builds."
    exit 0
fi

# ---------------------------------------------------------------------------
# Obfuscated build: obfuscate every C source, then compile.
# ---------------------------------------------------------------------------
mkdir -p "${OBF_DIR}"

echo "== obfuscating sources (tools/cobfuscate.py) =="
# Library first.
# shellcheck disable=SC2086
${OBF} "${LIB_SRC}" -o "${OBF_DIR}/envcheck.c" "${SEED_ARGS[@]}" --stats

for n in "${EXAMPLES[@]}"; do
    # shellcheck disable=SC2086
    ${OBF} "${ROOT}/examples/${n}.c" -o "${OBF_DIR}/${n}.c" "${SEED_ARGS[@]}" --stats
done
# shellcheck disable=SC2086
${OBF} "${ROOT}/demo/demo.c" -o "${OBF_DIR}/demo.c" "${SEED_ARGS[@]}" --stats

echo
echo "== compiling obfuscated sources =="
for n in "${EXAMPLES[@]}"; do
    echo "CC   ${n}.obf"
    # shellcheck disable=SC2086
    "${CC}" ${CFLAGS} ${OBF_CFLAGS} ${INC} \
        "${OBF_DIR}/${n}.c" "${OBF_DIR}/envcheck.c" -o "${BUILD}/${n}.obf"
done
echo "CC   demo.obf"
# shellcheck disable=SC2086
"${CC}" ${CFLAGS} ${OBF_CFLAGS} "${OBF_DIR}/demo.c" -o "${BUILD}/demo.obf"

echo
echo "Built obfuscated -> ${BUILD}/*.obf   (obfuscated sources in ${OBF_DIR}/)"
echo "Compare before/after, e.g.:"
echo "  strings ./build/demo    | grep OBFUSCATE     # plain: visible"
echo "  strings ./build/demo.obf | grep OBFUSCATE    # obfuscated: gone"
