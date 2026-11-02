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
#   ./run_tests.sh -st                          fail cases that ran past http_timeout
#
# Baselines are per CUBRID version. Pass the version as a bare argument to pick
# the directory they live in; without one, 11.5 is used.
#   ./run_tests.sh -a  11.4 task_result_check.txt
#   ./run_tests.sh -fc 11.4 task_result_check.txt
#   ./run_tests.sh --all                        run every set in task_test_case/
#                                               but those run only by name
#   ./run_tests.sh --clean                      drop log/ and the .result files
#   ./run_tests.sh --check-docs                 check that docs/api match the task tables
#
# Anything else is passed through to test_tasks.py, so --dump works too:
#   ./run_tests.sh --dump getbrokersinfo checkfile

set -u

cd "$(dirname "$0")" || exit 1

PYTHON=${PYTHON:-python3}
CASE_ROOT=task_test_case
LOG_DIR=log

# Sets that --all leaves out, because they need a particular environment;
# they run only when named. task_session_ip_check sends requests from
# 127.0.0.1 and 127.0.0.2, so it needs cmsip 127.0.0.1 on a Linux host
# (README.md 4.10).
NAMED_ONLY_SETS="task_session_ip_check.txt"

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
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
    --check-docs)
        # The required authority in docs/api is generated from the task
        # tables; fail when a document no longer matches them.
        exec "$PYTHON" ../../docs/api/tools/gen_task_authority.py --check ;;
esac

mkdir -p "$LOG_DIR"

if [ "${1:-}" = "--all" ]; then
    shift
    status=0
    for listfile in "$CASE_ROOT"/*.txt; do
        setname=$(basename "$listfile")
        case " $NAMED_ONLY_SETS " in
            *" $setname "*)
                echo "===== $setname (skipped: run it by name) ====="
                continue ;;
        esac
        echo "===== $setname ====="
        "$PYTHON" test_tasks.py "$setname" "$@" || status=1
    done
    exit $status
fi

exec "$PYTHON" test_tasks.py "$@"
