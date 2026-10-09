#!/bin/bash
# CMS API test driver.
#
# Replaces the old Makefile. A "test set" is a list file under task_test_case/
# plus the directory of cases it names; the reports are named after the set.
#
#   ./run_tests.sh                              run task_status_check
#   ./run_tests.sh task_result_check.txt        run another set
#   ./run_tests.sh -fc task_result_check.txt    compare against the .answer files
#   ./run_tests.sh -a task_result_check.txt     regenerate those .answer files
#   ./run_tests.sh -ns                          ignore the "sleep" lines
#
# Baselines are per CUBRID version. Pass the version as a bare argument to pick
# the directory they live in; without one, 11.4 is used.
#   ./run_tests.sh -a  11.4 task_result_check.txt
#   ./run_tests.sh -fc 11.4 task_result_check.txt
#   ./run_tests.sh --all                        run every set in task_test_case/
#   ./run_tests.sh --clean                      drop log/ and the .result files
#
# Anything else is passed through to test_tasks.py, so --dump works too:
#   ./run_tests.sh --dump getbrokersinfo checkfile

set -u

cd "$(dirname "$0")" || exit 1

PYTHON=${PYTHON:-python3}
CASE_ROOT=task_test_case
LOG_DIR=log

usage() {
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
}

clean() {
    rm -rf "$LOG_DIR"
    find "$CASE_ROOT" -name "*.result" -delete
    echo "removed $LOG_DIR and the .result files"
}

if [ ! -d "$CASE_ROOT" ]; then
    echo "run from server/test: $CASE_ROOT not found" >&2
    exit 1
fi

case "${1:-}" in
    -h|--help)  usage; exit 0 ;;
    --clean)    clean; exit 0 ;;
esac

mkdir -p "$LOG_DIR"

if [ "${1:-}" = "--all" ]; then
    shift
    status=0
    for listfile in "$CASE_ROOT"/*.txt; do
        setname=$(basename "$listfile")
        echo "===== $setname ====="
        "$PYTHON" test_tasks.py "$setname" "$@" || status=1
    done
    exit $status
fi

exec "$PYTHON" test_tasks.py "$@"
