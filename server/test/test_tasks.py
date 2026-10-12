#! /usr/bin/env python3
import atexit
import datetime
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from getpass import getpass

CONFIG_FILE = "test_tasks.conf"

TEST_CASE_ROOT = "task_test_case/"
DEFAULT_TEST_SET = "task_status_check.txt"
TEST_CONFIG_DIR = "task_test_config/"

KNOWN_VERSIONS = ("10_2", "11_0", "11_2", "11_3", "11_4", "11_5")
DEFAULT_VERSION = "11_4"
# Where start_kill_targets() records the processes it spawned, so that a run
# killed before clean_env() can be cleaned up by the next one.
HELPER_PID_FILE = "log/helper_pids"

# Every database the task list creates. They are removed before and after a run
TEST_DBS = ("alatestdb", "compactdbtest", "destinationdb", "anotherdb",
            "copydb", "destinationdb1", "renameadvdb", "renamedadvdb",
            "optionaldb")

# Sets that drive an instance this host does not own. Everything the suite does
# around the task list -- reset_leftovers(), the "cubrid service" bounce in
# restart_services(), the files build_env() drops under $CUBRID, and the
# clean_env()/stop_services() pair that undoes them -- acts on the machine the
# suite runs on, never on the one the requests go to. For the HA set that work
# is at best useless and at worst destructive: run on the HA node itself, the
# "cubrid service stop" would tear down the very heartbeat the set exercises.
# These sets therefore take the server as they find it and leave it that way.
NO_LOCAL_ENV_SETS = ("task_ha_result_check",)


def resolve_test_set(listarg):
    """Return (list path, case directory, report base name) for a test set.

    The set is named by its list file. A bare name is looked up under
    task_test_case/, so both "task_result_check.txt" and
    "task_test_case/task_result_check.txt" work.
    """
    listpath = listarg
    if not os.path.dirname(listpath):
        listpath = os.path.join(TEST_CASE_ROOT.rstrip("/"), listpath)
    base = os.path.basename(listpath)
    if base.endswith(".txt"):
        base = base[:-4]
    return listpath, os.path.join(os.path.dirname(listpath), base), base


def case_path(name):
    return os.path.join(CASE_DIR, name)


def normalize_version(value):
    """Accept "11.4" or "11_4" and return the directory form, "11_4"."""
    text = value.strip().replace(".", "_")
    if not re.match(r"^\d+_\d+$", text):
        return None
    return text


def answer_dir():
    return os.path.join(CASE_DIR, VERSION)


def answer_base(slot):
    """Path of the baseline pair for one case occurrence, minus the suffix."""
    return os.path.join(answer_dir(), slot)


def parse_list_line(line):
    """Split a scenario line into (case name, expected status, status only).

    A line is either

        <case>              compared against <case>.answer by --file-check
        <case>,<status>      checked by its status field only

    The comma form is what marks a case as status only: negative cases
    (`userverify_fail,failure`) and cases whose response cannot have a stable
    baseline (`loadaccesslog,success`). Those never get an .answer, and
    --file-check judges them by the status they declare.
    """
    name, comma, expected = line.partition(",")
    expected = expected.strip()
    return name.strip(), (expected or "success"), bool(comma)


# Values that differ on every run even when the server behaves identically:
# process ids, elapsed times, cpu/memory samples, free space and the sizes of
# log files the run itself writes to. --file-check replaces them so that the
# comparison is about the shape and the stable content of the response.
VOLATILE_KEYS = frozenset((
    "pid", "as_pid", "as_psize", "as_lat",
    "time", "tran_time", "tranindex",
    "cpu_kernel", "cpu_user", "cpu_idle", "cpu_iowait",
    "mem_physical", "mem_virtual", "mem_phy_free",
    "free_size", "freespace", "size", "total",
    "token",
))

# Timestamps and temporary file names are embedded in longer strings, so they
# are masked by shape rather than by key.
VOLATILE_PATTERNS = (
    # Temporary files the server names with a counter and a clock, e.g.
    # "$CUBRID/tmp/log_run_res_142_1787268395_295". Masked first: the
    # timestamp patterns below would otherwise cut them in half.
    (re.compile(r"((?:analyzelog_res|log_run_res2?|statustemplate_update"
                r"|loaddb_err_tmp|DBMT_task[A-Za-z_]*)_)[0-9][0-9_]*"),
     r"\1<tmpid>"),
    # "Fri Aug 21 08:11:54 2026"
    (re.compile(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}"),
     "<timestamp>"),
    # "2026.08.21 08:12", "2026/08/21 08:12:27", "2026.08.21.08.12"
    (re.compile(r"\d{4}[-./]\d{2}[-./]\d{2}[ T.]\d{2}[:.]\d{2}([:.]\d{2})?"),
     "<timestamp>"),
    # "demodb_20260821_0813.err"
    (re.compile(r"\d{8}_\d{4}(?=\.)"), "<timestamp>"),
    # "2026.08.21"
    (re.compile(r"\d{4}[-./]\d{2}[-./]\d{2}"), "<date>"),
    # "Last_lsa: 781|3000" -- the log position moves with every write
    (re.compile(r"(_lsa(?: was)?:? )-?\d+\|-?\d+"), r"\1<lsa>"),
    # Aligned counter lines of a statistics dump, "Hits:            156".
    # plandump is nothing but these, and they count everything the run did
    # before reaching the case. Masking the number keeps the shape of the dump
    # comparable -- a section that stops being reported is still caught.
    (re.compile(r"^(\s*[A-Za-z][A-Za-z0-9_ ]*:[ \t]{2,})\d+$"), r"\1<count>"),
)


def normalize_response(body):
    """Reduce a response to the part that must not change between runs.

    The raw body carries values that differ on every run (elapsed times, pids,
    the host name, absolute paths), so comparing it verbatim would fail even
    when the server behaves identically. Those are dropped or put back into the
    placeholder form the request used; everything else is compared as is.
    """
    try:
        data = json.loads(body)
    except ValueError:
        return body.strip() + "\n"

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for key, value in node.items():
                if key == "__EXEC_TIME":
                    continue
                out[key] = "<volatile>" if key in VOLATILE_KEYS else walk(value)
            return out
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, str):
            return mask_paths(node)
        return node

    text = json.dumps(walk(data), indent=3, sort_keys=True, ensure_ascii=False)
    return text + "\n"


def mask_paths(value):
    """Put the run specific parts of a string into placeholder form."""
    if CUBRID_DATABASES:
        value = value.replace(str(CUBRID_DATABASES), "$CUBRID_DATABASES")
    if CUBRID:
        value = value.replace(str(CUBRID), "$CUBRID")
    value = value.replace(HOSTNAME, "$HOSTNAME")
    for pattern, placeholder in VOLATILE_PATTERNS:
        value = pattern.sub(placeholder, value)
    return value


def load_config():
    """Read the address of the instance under test from CONFIG_FILE.

    The port used to be read from the local $CUBRID/conf/cm.conf, which only
    describes the manager server installed on this host. The suite drives one
    that is not necessarily here, so where to send the requests is
    configuration rather than something to discover locally.

    The file is required. A default host would either test nothing or, worse,
    test whichever server happens to answer at that address, so a missing or
    unreadable file stops the run before the first request goes out.

    "cmsip 192.168.2.80" and "cmsip=192.168.2.80" are both read, "#" starts a
    comment.
    """
    conf = os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_FILE)
    if not os.path.isfile(conf):
        print("\033[31mno %s: the tests cannot start.\033[0m" % conf)
        print("Create it with the manager server to run against, for example")
        print("")
        print("    cmsip 192.168.2.80")
        print("    port 8001")
        sys.exit(1)

    settings = {}
    with open(conf, "r") as cf:
        for lineno, line in enumerate(cf, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            match = re.match(r"^([A-Za-z_][A-Za-z_0-9]*)\s*=?\s*(\S+)$", line)
            if not match:
                print("\033[31m%s line %d: cannot read %r\033[0m"
                      % (conf, lineno, line))
                sys.exit(1)
            settings[match.group(1)] = match.group(2)

    missing = [key for key in ("cmsip", "port") if key not in settings]
    if missing:
        print("\033[31m%s does not set %s.\033[0m"
              % (conf, " or ".join(missing)))
        sys.exit(1)
    if not settings["port"].isdigit():
        print("\033[31m%s: port must be a number, not %r\033[0m"
              % (conf, settings["port"]))
        sys.exit(1)
    return settings["cmsip"], int(settings["port"])


cmsip, port = load_config()
url = "/cm_api"

token = ""
CUBRID = ""
CUBRID_DATABASES = ""

results = []

# Placeholders whose value is only known once the run has started, see
# start_kill_targets().
runtime_vars = {}
helper_procs = []

# The manager server serves cm_port over TLS with a self signed certificate,
# so the certificate of the host under test is not verified here.
ssl_context = ssl._create_unverified_context()


def exec_task(ip, port, url, body):
    """Send one request to the manager server.

    A refused connection means the manager is not running, which is worth
    saying plainly: as a traceback out of http.client it reads like a bug in
    the runner rather than a service that has to be started first.
    """
    import http.client
    conn = http.client.HTTPSConnection(ip, port, context=ssl_context)
    try:
        conn.request("POST", url, body)
        return conn.getresponse().read()
    except (ConnectionError, socket.error) as exc:
        print("\033[31mcannot reach the manager server at %s:%s (%s).\033[0m"
              % (ip, port, exc))
        print("start it with 'cubrid service start' on that host, or check "
              "cmsip and port in %s." % CONFIG_FILE)
        sys.exit(1)
    finally:
        conn.close()


def replace_env_vars(contents):
    """Substitute the placeholders a test case may use.

    The $AUTO_* ones are set to the next minute so that a scheduled job created
    by the test is due right after the request.
    """
    next_minute = datetime.datetime.now() + datetime.timedelta(minutes=1)
    contents = contents.replace("$AUTO_DATE", next_minute.strftime("%Y-%m-%d"))
    contents = contents.replace("$AUTO_TIME", next_minute.strftime("%H%M"))
    contents = contents.replace("$AUTO_QUERY_TIME",
                                next_minute.strftime("%Y/%m/%d %H:%M"))
    for name, value in runtime_vars.items():
        contents = contents.replace(name, value)
    contents = contents.replace("$CUBRID_DATABASES", str(CUBRID_DATABASES))
    contents = contents.replace("$CUBRID", str(CUBRID))
    return contents


def load_task(taskfile):
    with open(taskfile, "r") as task:
        return json.loads(replace_env_vars(task.read()))


def record(name, casefile, task, status, note, expected, response=None,
           quiet=False):
    """Log one result.

    Several cases share the same task name (renamedb, renamedb_adoff, ... all
    run the "renamedb" task), so the case file is what identifies a test. It
    leads every line, with the task it runs in brackets.

    `response` is kept for the detailed report only; the console output and the
    plain XML stay short.
    """
    ok = (status == expected)
    results.append({"name": name, "file": casefile, "task": task, "ok": ok,
                    "note": note, "response": response,
                    "status": status, "expected": expected})
    if quiet:
        # --file-check reports one verdict per case, from the comparison; the
        # per request status lines would only double every line of the log.
        return ok
    label = "%s [%s]" % (name, task)
    if ok:
        print(label + " : " + '\033[32m{0}\033[0m'.format(status))
    else:
        print(label + " : " + '\033[31mexpected {0}, got {1} ({2})\033[0m'.format(
            expected, status, note))
        print("    case file: %s" % casefile)
        print_response(response)
        if task in DIAGNOSE_TASKS:
            diagnose_db_state(task, casefile)
    return ok


# A failed response usually says more than its "note". Tasks that run a utility
# put its output in the response as well (ts_loaddb feeds both the stdout and
# the stderr of loaddb through file_to_nvpairs, then deletes the files), so the
# only place that output survives is the response itself. It used to reach the
# detailed XML and nowhere else, which meant reading an artifact to find out
# why a case failed.
RESPONSE_LINES = 40
RESPONSE_CHARS = 4000


def print_response(response):
    if not response:
        return
    try:
        text = json.dumps(json.loads(response), indent=3, sort_keys=True,
                          ensure_ascii=False)
    except (ValueError, TypeError):
        text = str(response)
    lines = text.split("\n")
    print("    --- response")
    for line in lines[:RESPONSE_LINES]:
        print("    " + line[:RESPONSE_CHARS])
    if len(lines) > RESPONSE_LINES:
        print("    ... %d more lines (full text in log/%s_detail.xml)"
              % (len(lines) - RESPONSE_LINES, REPORT_BASE))


def send_one(name, req, token, expected="success", casefile=""):
    req["token"] = token
    task = req.get("task", name)
    response = exec_task(cmsip, port, url, json.dumps(req))
    # Tasks that echo a log file back (loadaccesslog) can carry bytes that are
    # not valid UTF-8, because the server writes error messages with an
    # uninitialized buffer into the log. That is a server defect, but it must
    # not turn into a failure of whatever case happens to read the log.
    body = response.decode(errors="replace")
    try:
        data = json.loads(body)
    except ValueError:
        record(name, casefile, task, "invalid",
               "non JSON response: %s" % response[:200], expected, body,
               quiet=file_check)
        return {"task": task, "status": "failure"}
    # The raw body is kept verbatim: docs/api/*.md quote the server's own
    # formatting, so a re-serialized copy would not be comparable.
    record(name, casefile, task, data.get("status"), data.get("note", ""),
           expected, body, quiet=file_check)
    return data


case_runs = {}


def result_slot(name):
    """Baseline name for this occurrence of a case.

    A case may be listed more than once (startinfo runs before and after the
    databases the scenario creates), and the two runs answer differently. The
    second occurrence gets its own baseline instead of overwriting the first.
    """
    seen = case_runs.get(name, 0) + 1
    case_runs[name] = seen
    return name if seen == 1 else "%s.%d" % (name, seen)


def do_one_job(name, taskfile, token, expected="success", record_files=True,
               status_only=False):
    """Run one case: every request in it, then the answer handling.

    `status_only` comes from the ",<status>" form in the scenario file. Such a
    case is judged by its status field in every mode and never gets a baseline.
    """
    before = len(results)
    request = load_task(taskfile)
    if isinstance(request, list):
        for index, req in enumerate(request):
            data = send_one("%s[%d]" % (name, index), req, token, expected,
                            taskfile)
    else:
        data = send_one(name, request, token, expected, taskfile)
    # An array case sends several requests; its answer covers all of them, in
    # order, so that the file is the record of the whole case.
    entries = results[before:]
    bodies = [r["response"] for r in entries if r.get("response") is not None]
    text = "".join(normalize_response(b) for b in bodies)
    task = entries[0].get("task", name) if entries else name
    if record_files:
        slot = answer_base(result_slot(name))
        if status_only:
            # The status verdict already recorded is the whole answer here.
            if file_check:
                report_status_only(name, entries)
        elif file_check:
            check_against_answer(name, slot, text, entries)
        elif make_answer:
            write_answer(slot, text)
    return data


def write_answer(taskfile, text):
    """Record the response of this run as the baseline for `--file-check`.

    Only written with --answer. Regenerating a baseline is an explicit act: a
    plain run would otherwise quietly adopt whatever the server answered today
    as the thing to compare against tomorrow.
    """
    directory = os.path.dirname(taskfile)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(taskfile + ".answer", "w") as out:
        out.write(text)


def check_against_answer(name, taskfile, text, entries):
    """Compare this run against the stored baseline.

    In --file-check mode the verdict of a case is the comparison, not the
    status field: a case that answers "success" with different content is a
    failure, and a negative case that keeps failing the same way passes.

    A case that has no baseline is a failure: it is listed as one to compare,
    so the missing file is a gap to fill with --answer, not something to pass
    over quietly. Cases that cannot have a baseline say so in the scenario file
    with the ",<status>" form instead.
    """
    answerfile = taskfile + ".answer"
    if not os.path.isfile(answerfile):
        del results[len(results) - len(entries):]
        task = entries[0].get("task", name) if entries else name
        note = ("no %s; run with --answer %s once to create it"
                % (answerfile, VERSION.replace("_", ".")))
        results.append({"name": name, "file": taskfile, "task": task,
                        "ok": False, "note": note, "response": text})
        print("%s [%s] : " % (name, task)
              + '\033[31mfailed ({0})\033[0m'.format(note))
        return
    resultfile = taskfile + ".result"
    directory = os.path.dirname(resultfile)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(resultfile, "w") as out:
        out.write(text)
    with open(answerfile, "r") as f:
        expected_txt = f.read()
    ok = (expected_txt == text)
    note = "" if ok else "differs from %s" % answerfile
    # The requests of this case were already recorded by their status; replace
    # them with the single verdict of the comparison.
    del results[len(results) - len(entries):]
    task = entries[0].get("task", name) if entries else name
    results.append({"name": name, "file": taskfile, "task": task, "ok": ok,
                    "note": note, "response": text})
    label = "%s [%s]" % (name, task)
    if ok:
        print(label + " : " + '\033[32msuccess\033[0m')
    else:
        print(label + " : " + '\033[31mfailed ({0})\033[0m'.format(note))
        print("    %s" % first_difference(expected_txt, text))


def report_status_only(name, entries):
    """Print the status verdict of a case the scenario marked as status only.

    The per request lines were recorded quietly because --file-check normally
    prints one verdict per case; for these they are the verdict, so they are
    printed here.
    """
    for item in entries:
        item["status_only"] = True
        label = "%s [%s]" % (item["name"], item.get("task", name))
        if item["ok"]:
            print(label + " : " + '\033[32m{0}\033[0m (status only)'
                  .format(item["status"]))
        else:
            print(label + " : "
                  + '\033[31mexpected {0}, got {1} ({2})\033[0m'.format(
                      item["expected"], item["status"], item["note"]))


SLEEP_LINE = re.compile(r"^sleep[ \t]+(\d+(?:\.\d+)?)$")


def do_all_jobs(token):
    with open(LIST_FILE, "r") as tasks:
        for line in tasks:
            line = line.rstrip()
            if line == "":
                continue
            if line[0] == '/':
                print('\n\033[33m{0}\033[0m'.format(line))
                continue
            # "sleep <seconds>" waits before the next case. Tasks that answer
            # before their work is done need it: the request returns, but the
            # database is still busy, and the next case on the same database is
            # refused while it is. It is a scenario decision, not a property of
            # a case, so it lives in the list rather than in a case file.
            wait = SLEEP_LINE.match(line)
            if wait:
                if no_sleep:
                    # A server that answers only when the work is done has
                    # nothing to wait for, and the waits are the bulk of the
                    # run; the same list then serves both kinds of server.
                    print("\033[33m%s (ignored, --no-sleep)\033[0m" % line)
                    continue
                seconds = float(wait.group(1))
                print("sleep %s" % wait.group(1))
                time.sleep(seconds)
                continue
            name, expected, status_only = parse_list_line(line)
            do_one_job(name, case_path(name), token, expected,
                       status_only=status_only)


def first_difference(expected_txt, actual):
    """Point at the first differing line, so the log says what moved."""
    exp = expected_txt.split("\n")
    got = actual.split("\n")
    for i in range(max(len(exp), len(got))):
        a = exp[i] if i < len(exp) else "<missing>"
        b = got[i] if i < len(got) else "<missing>"
        if a != b:
            return "line %d: answer %s / result %s" % (i + 1, a.strip(), b.strip())
    return "no line differs (trailing content only)"


def dump_one(name, token):
    """Run a single task case with the real token and print its raw response.

    Used to capture actual response values, e.g. to verify or update the API
    documentation. The stale token in the case file is replaced with `token`.
    """
    request = load_task(case_path(name))
    reqs = request if isinstance(request, list) else [request]
    for req in reqs:
        req["token"] = token
        response = exec_task(cmsip, port, url, json.dumps(req))
        try:
            data = json.loads(response.decode(errors="replace"))
            print(json.dumps(data, indent=3, sort_keys=True, ensure_ascii=False))
        except ValueError:
            print(response.decode(errors="replace"))


def stop_test_servers():
    """Shut down any server still running for a database the suite creates.

    A stopdb that does not finish leaves "cub_server <db>" behind. Deleting the
    directory underneath it does not kill it, and the next run then fails on
    "database is active" or on volumes it cannot mount, so the damage carries
    over from run to run until someone kills the process by hand.
    """
    cubrid_bin = os.path.join(CUBRID, "bin", "cubrid")
    for name in TEST_DBS:
        if subprocess.call(["pgrep", "-f", "^cub_server %s$" % name],
                           stdout=subprocess.DEVNULL) != 0:
            continue
        subprocess.call([cubrid_bin, "server", "stop", name],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["pkill", "-9", "-f", "^cub_server %s$" % name],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def reset_test_dbs():
    """Drop whatever a previous run left behind.

    A run that dies half way through leaves database directories and
    databases.txt entries around, and the next run then fails on names that are
    already taken. Only the databases the suite creates itself are touched.
    """
    stop_test_servers()
    for name in TEST_DBS:
        shutil.rmtree(os.path.join(CUBRID_DATABASES, name), ignore_errors=True)

    dblist = os.path.join(CUBRID_DATABASES, "databases.txt")
    try:
        with open(dblist, "r") as f:
            lines = f.readlines()
    except IOError:
        return
    def is_test_db(line):
        fields = line.split()
        return not line.startswith("#") and fields and fields[0] in TEST_DBS

    kept = [l for l in lines if not is_test_db(l)]
    if len(kept) != len(lines):
        with open(dblist, "w") as f:
            f.writelines(kept)


def probe(request):
    """Run a task without recording it, for the setup code below."""
    request["token"] = token
    try:
        return json.loads(exec_task(cmsip, port, url, json.dumps(request)).decode())
    except ValueError:
        return {}


def find_tranindex(pid, timeout=15):
    """Return the transaction index demodb gave the client running as `pid`.

    The index is reported as "1(ACTIVE)" but killtran wants a bare number.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = probe({"task": "gettransactioninfo", "dbname": "demodb"})
        for entry in data.get("transactioninfo", []):
            for tran in entry.get("transaction", []):
                if tran.get("pid") == str(pid):
                    match = re.match(r"\d+", tran.get("tranindex", ""))
                    if match:
                        return match.group(0)
        time.sleep(0.5)
    return ""


def record_helper_pid(proc):
    """Remember a helper process so a killed run can be cleaned up later.

    clean_env() is skipped when the run dies on SIGKILL, and the sleep would
    then sit there for an hour while the csql session keeps a transaction open
    on demodb. The pid is written together with the command line so the next
    run only kills a pid that is still the process we started.
    """
    helper_procs.append(proc)
    directory = os.path.dirname(HELPER_PID_FILE)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(HELPER_PID_FILE, "a") as f:
        f.write("%d %s\n" % (proc.pid, " ".join(proc.args)))


def sweep_stale_helpers():
    """Kill helpers a previous run left behind, and only those."""
    try:
        with open(HELPER_PID_FILE) as f:
            entries = [line.split(None, 1) for line in f if line.strip()]
    except IOError:
        return
    for pid, cmdline in entries:
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as f:
                running = f.read().replace(b"\0", b" ").decode().strip()
        except IOError:
            continue        # already gone, or not ours any more
        if running == cmdline.strip():
            print("killing helper left over from an earlier run: %s %s"
                  % (pid, running))
            try:
                os.kill(int(pid), signal.SIGKILL)
            except OSError:
                pass
    os.remove(HELPER_PID_FILE)


def open_transaction():
    """Open a transaction on demodb and leave it open.

    With autocommit off the transaction lives until the process exits, and the
    process exits on its own when the runner dies, because stdin is a pipe.
    """
    csql = subprocess.Popen(
        [os.path.join(CUBRID, "bin", "csql"), "--CS-mode", "-u", "dba", "demodb"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, universal_newlines=True)
    record_helper_pid(csql)
    csql.stdin.write(";autocommit off\nselect count(*) from db_class;\n")
    csql.stdin.flush()
    return csql


def start_kill_targets():
    """Give killprocess and killtransaction something that really exists.

    Both cases used to carry a hardcoded id (pid 99999, tranindex "2(+)"), so
    they failed on every host. The suite now creates its own victims and passes
    their real ids in through $TEST_KILL_PID / $TEST_TRANINDEX.
    """
    sweep_stale_helpers()

    dummy = subprocess.Popen(["sleep", "3600"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    record_helper_pid(dummy)
    runtime_vars["$TEST_KILL_PID"] = str(dummy.pid)

    # Two transactions, not one: killtransaction reports the transactions that
    # are still there after the kill, so with a single victim it can only ever
    # answer "transactioninfo": null. The second one is the bystander.
    victim, bystander = (open_transaction(), open_transaction())

    tranindex = find_tranindex(victim.pid)
    if not tranindex:
        print("\033[33mno transaction found on demodb, killtransaction will "
              "fail.\033[0m")
    runtime_vars["$TEST_TRANINDEX"] = tranindex
    if not find_tranindex(bystander.pid):
        print("\033[33monly one transaction on demodb, killtransaction will "
              "report an empty list.\033[0m")


def stop_kill_targets():
    for proc in helper_procs:
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
    del helper_procs[:]
    try:
        os.remove(HELPER_PID_FILE)
    except OSError:
        pass


def make_loaddb_input(tmpdir):
    """Unload demodb into a throwaway schema/objects pair for the loaddb case.

    loaddb runs with delete_orignal_files=y, so it consumes whatever it is
    pointed at. It used to be pointed at demodb's own dump, which the unloaddb
    case (much later in the list) regenerates -- meaning loaddb was really
    reading the *previous* run's output, and a run that died in between broke
    the next one with "file does not exists". Its input is now produced here.
    """
    for suffix in ("schema", "objects", "indexes", "trigger"):
        try:
            os.remove(os.path.join(tmpdir, "test_loaddb_%s" % suffix))
        except OSError:
            pass
    subprocess.call([os.path.join(CUBRID, "bin", "cubrid"), "unloaddb",
                     "--CS-mode", "-u", "dba", "-O", tmpdir,
                     "--output-prefix", "test_loaddb", "demodb"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def demodb_is_up():
    return subprocess.call(["pgrep", "-f", "^cub_server demodb$"],
                           stdout=subprocess.DEVNULL) == 0


def wait_for_mon_data(timeout=120):
    """Wait until the monitoring gather has registered the volumes.

    set_mon_interval resizes vol_mon, and that file is only created once a
    gather run has registered the volumes of a database. Called straight after
    a restart it would find no file and fail, and the failed reset_meta leaves
    the meta inconsistent for good, so the run has to wait for the first sample
    before it touches any of the monitoring cases.

    The volumes come from spacedb, so they are only registered while the
    database is up. With demodb down the gather still writes db_mon and leaves
    k_total_vol_num at 0 for good -- waiting the full timeout would only delay
    the run before the same failure, so that case is reported at once.
    """
    meta = os.path.join(CUBRID, "var", "manager", "mon_data", "meta.json")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(meta) as f:
                if json.load(f).get("k_total_vol_num", 0) > 0:
                    return True
        except (IOError, ValueError):
            pass
        if not demodb_is_up():
            print("\033[33mdemodb is not running, so the monitoring gather "
                  "cannot register its volumes: set_mon_interval and the "
                  "volume cases of get_mon_statistic will fail. Start demodb "
                  "and run again.\033[0m")
            return False
        time.sleep(2)
    print("\033[33mno monitoring data collected within %d s; the "
          "set_mon_interval and get_mon_statistic cases will fail. Check "
          "support_mon_statistic in cm.conf.\033[0m" % timeout)
    return False


def build_env():
    """Create what the test cases expect to find on the host."""
    # reset_leftovers() already did this with the paths from the environment;
    # repeat it with the ones getenv reported, in case they are not the same.
    reset_test_dbs()
    # copydb_advance copies a database into this directory.
    dest = os.path.join(CUBRID_DATABASES, "destinationdb1")
    if not os.path.isdir(dest):
        os.makedirs(dest)
    # getcaslogtopresult and removecasrunnertmpfile read these files.
    tmpdir = os.path.join(CUBRID, "tmp")
    srcdir = os.path.join(TEST_CONFIG_DIR, "tmp_file_for_test")
    for name in os.listdir(srcdir):
        shutil.copy(os.path.join(srcdir, name), tmpdir)
    # removelog deletes the file it is given, so give it a disposable one.
    with open(os.path.join(tmpdir, "test_removelog.log"), "w") as f:
        f.write("dummy log line for removelog test\n")
    # runscript only accepts a path under $CUBRID or $CUBRID_DATABASES, so the
    # script it runs has to be created there.
    script = os.path.join(tmpdir, "test_runscript.sh")
    with open(script, "w") as f:
        f.write("#!/bin/sh\necho runscript test\n")
    os.chmod(script, 0o755)
    # analyzecaslog runs broker_log_top over a broker SQL log. Pointed at a live
    # CAS log it answers "resultlist": null, because nothing in this suite sends
    # SQL through a broker and broker_log_top then writes an empty report. This
    # fixture carries two executed queries so the parsing is actually covered.
    shutil.copy(os.path.join(TEST_CONFIG_DIR, "test_analyzecaslog.sql.log"), tmpdir)
    # getfolderswithkeyword searches for directories whose name contains the
    # keyword ("res"). Without one it answers "folders": null.
    folder = os.path.join(tmpdir, "test_result_folder")
    if not os.path.isdir(folder):
        os.makedirs(folder)
    make_loaddb_input(tmpdir)
    # adddbmtuser creates "yifan" and deletedbmtuser drops it again. A run that
    # died between the two leaves the user behind, and the next adddbmtuser
    # then fails with "already exist"; this is a no-op when it is not there.
    probe({"task": "deletedbmtuser", "targetid": "yifan"})
    wait_for_mon_data()
    start_kill_targets()


def clean_env():
    """Remove what this run created. Runs from the finally block."""
    stop_kill_targets()
    reset_test_dbs()


def reset_leftovers():
    """Do the end of run cleanup again, before this run starts.

    clean_env() only runs when the run reaches its finally block; a run killed
    with SIGKILL, or one that died on a service that would not come back, never
    gets there and leaves its databases, its stray cub_server processes and its
    helper processes behind. Repeating the work up front means a broken run
    poisons at most itself.

    It runs before restart_services() on purpose: a stray "cub_server <db>" has
    to go before "cubrid service stop", not after, or the service comes back up
    with it still holding volumes that are about to be deleted.

    The paths come from the environment here, because the authoritative ones
    are only known after getenv, which needs a server that is not up yet.
    build_env() repeats reset_test_dbs() with those values in case the two
    disagree.
    """
    global CUBRID, CUBRID_DATABASES
    CUBRID = os.environ["CUBRID"]
    CUBRID_DATABASES = os.environ["CUBRID_DATABASES"]
    print("cleaning up after any earlier run ...")
    sweep_stale_helpers()
    reset_test_dbs()


def xml_escape(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def detail_xml_path(path):
    """`log/result.xml` -> `log/result_detail.xml`."""
    root, ext = os.path.splitext(path)
    return root + "_detail" + ext


def write_junit_xml(path, with_response=False):
    """Write the report the CI job collects.

    Two files are produced: the plain one stays small enough to skim, and the
    "_detail" one carries the full response of every case in <system-out>, so
    that the documented samples in docs/api/*.md can be checked against what
    the server really answers without re-running anything.
    """
    failures = sum(1 for r in results if not r["ok"])
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)

    with open(path, "w") as out:
        out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        out.write('<testsuites tests="%d" failures="%d" disabled="0" '
                  'errors="0" time="0" name="AllTests">\n'
                  % (len(results), failures))
        out.write('<testsuite name="CMSERVER_TEST" tests="%d" failures="%d" '
                  'disabled="0" errors="0" time="0">\n'
                  % (len(results), failures))
        for item in results:
            out.write('<testcase name="%s" file="%s" task="%s" status="run" '
                      'time="0" classname="CMSERVER_TEST">\n'
                      % (xml_escape(item["name"]), xml_escape(item["file"]),
                         xml_escape(item.get("task", ""))))
            if not item["ok"]:
                out.write('<failure message="%s" type=""></failure>\n'
                          % xml_escape(item["note"]))
            if with_response and item.get("response") is not None:
                # A "]]>" inside the payload would close the section early.
                body = item["response"].replace("]]>", "]]]]><![CDATA[>")
                out.write('<system-out><![CDATA[\n%s\n]]></system-out>\n' % body)
            out.write('</testcase>\n')
        out.write('</testsuite>\n</testsuites>\n')


def wait_for_manager(timeout=90):
    """Block until the manager server answers on cm_port again."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            exec_task(cmsip, port, url, json.dumps({"task": "keepalive"}))
            return True
        except Exception:
            time.sleep(1)
    print("\033[31mthe manager server did not come back up within %d s.\033[0m"
          % timeout)
    return False


def reset_mon_data(cubrid_home):
    """Throw away the monitoring statistics files.

    They have to go while the service is down. cub_manager rebuilds them on the
    way up, and only a rebuilt set is guaranteed to be consistent: reset_meta()
    resizes broker/db/volume/os files one by one and updates k_interval last, so
    a failure in the middle (a missing vol_mon, for instance) leaves the files
    sized for the new interval and the meta claiming the old one. Once that
    happens set_mon_interval fails on every later call and the yearly
    get_mon_statistic reads past the end of the file.
    """
    mon_dir = os.path.join(cubrid_home, "var", "manager", "mon_data")
    if not os.path.isdir(mon_dir):
        return
    for name in os.listdir(mon_dir):
        try:
            os.remove(os.path.join(mon_dir, name))
        except OSError:
            pass


def run_service_cmd(args, what, timeout=300):
    """Run one cubrid service command, bounded and not silenced.

    These used to be subprocess.call with the output thrown away, which meant a
    command that never returned looked exactly like a suite that had stopped
    printing.

    The output goes to a file rather than a pipe on purpose. "cubrid service"
    forks children that inherit its stdout, so a pipe stays open after the
    command itself is killed and reading it would block for as long as any
    grandchild lives -- the timeout would expire and the run would still hang,
    which is what a pipe version of this did. For the same reason the command
    gets its own process group, so the whole tree can be killed at once.
    """
    print("  %s ..." % what)
    outfile = tempfile.NamedTemporaryFile(prefix="cubrid_service_",
                                          suffix=".log", delete=False)
    returncode = None
    try:
        proc = subprocess.Popen(args, stdout=outfile, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            print("    \033[31m'%s' did not return within %d s; killing it\033[0m"
                  % (" ".join(args), timeout))
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                pass
            proc.wait(timeout=30)
    finally:
        outfile.close()
    with open(outfile.name, errors="replace") as f:
        output = f.read().strip()
    os.remove(outfile.name)
    for line in output.split("\n")[-20:]:
        if line:
            print("    " + line)
    if not output:
        print("    (no output)")
    return returncode


# Tasks whose failure message says what did not happen but nothing about why.
# "stopdb: execute timeout" only means the database did not come down inside
# the 30 s the manager waits; what was still holding it has to be looked at
# while it is still true, so it is collected here rather than guessed at later.
DIAGNOSE_TASKS = frozenset(("stopdb", "get_mon_statistic", "loaddb"))


def diagnose_mon_meta():
    """Print what the monitoring meta actually holds.

    "Can't find volname[...]" says the volume asked for is not registered, but
    not what is registered instead, and the answer changes as gathers run.
    """
    meta = os.path.join(CUBRID, "var", "manager", "mon_data", "meta.json")
    print("    --- monitoring meta")
    try:
        with open(meta) as f:
            data = json.load(f)
    except (IOError, ValueError) as exc:
        print("      cannot read %s: %s" % (meta, exc))
        return
    print("      k_total_vol_num: %s" % data.get("k_total_vol_num"))
    print("      k_interval: %s" % data.get("k_interval"))
    print("      k_db_rrd: %s" % json.dumps(data.get("k_db_rrd"), indent=None))
    print("      meta.json mtime: %s"
          % time.strftime("%H:%M:%S", time.localtime(os.path.getmtime(meta))))
    print("      now:             %s" % time.strftime("%H:%M:%S"))


def diagnose_loaddb(request):
    """Print what loaddb was pointed at, and its own log.

    loaddb consumes files this suite produced earlier in the run, and a case
    ahead of it may have deleted them (delete_orignal_files) or left them
    half written. Whether they are there at all is the first thing to know.
    """
    print("    --- loaddb input")
    for key in ("schema", "object", "index"):
        value = request.get(key)
        if not value or value == "none":
            print("      %-8s %s" % (key, value or "(not given)"))
            continue
        path = replace_env_vars(value)
        if os.path.isfile(path):
            print("      %-8s %s (%d bytes)"
                  % (key, path, os.path.getsize(path)))
        else:
            print("      %-8s %s \033[31m(missing)\033[0m" % (key, path))

    # loaddb writes <db>_loaddb.log next to wherever it ran.
    dbname = request.get("dbname", "")
    for root in (os.getcwd(), CUBRID, CUBRID_DATABASES,
                 os.path.join(CUBRID_DATABASES, dbname)):
        log = os.path.join(root, "%s_loaddb.log" % dbname)
        if os.path.isfile(log):
            print("    %s (last 20 lines):" % log)
            with open(log, errors="replace") as f:
                for line in f.read().split("\n")[-20:]:
                    if line:
                        print("      " + line)
            return
    print("    no %s_loaddb.log found" % dbname)


def diagnose_db_state(task, casefile):
    """Print who still has the database of a failed case."""
    if task == "get_mon_statistic":
        diagnose_mon_meta()
        return
    if task == "loaddb":
        try:
            request = load_task(casefile)
        except Exception:
            return
        if isinstance(request, list):
            request = request[0] if request else {}
        diagnose_loaddb(request)
        return
    try:
        request = load_task(casefile)
    except Exception:
        return
    if isinstance(request, list):
        request = request[0] if request else {}
    dbname = request.get("dbname")
    if not dbname:
        return

    print("    --- state after %s(%s) failed" % (task, dbname))
    cubrid_bin = os.path.join(CUBRID, "bin", "cubrid")
    for args, what in (([cubrid_bin, "server", "status"], "server status"),
                       ([cubrid_bin, "broker", "status"], "broker status")):
        try:
            done = subprocess.run(args, timeout=30, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
            out = done.stdout.decode(errors="replace").strip()
        except Exception as exc:
            out = "could not run: %s" % exc
        print("    %s:" % what)
        for line in out.split("\n")[:15]:
            print("      " + line)

    # Processes that keep a database open are what a stop waits for.
    try:
        done = subprocess.run(["ps", "-eo", "pid,user,args"], timeout=30,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = [l for l in done.stdout.decode(errors="replace").split("\n")
                 if ("cub_server" in l or "cub_cas" in l or "csql" in l)
                 and "grep" not in l]
    except Exception as exc:
        lines = ["could not list processes: %s" % exc]
    print("    processes holding a database:")
    for line in lines[:15]:
        print("      " + line.strip())

    logdir = os.path.join(CUBRID, "log", "server")
    try:
        logs = sorted((os.path.join(logdir, f) for f in os.listdir(logdir)
                       if f.startswith(dbname)), key=os.path.getmtime)
    except OSError:
        logs = []
    if logs:
        print("    %s (last 20 lines):" % logs[-1])
        with open(logs[-1], errors="replace") as f:
            for line in f.read().split("\n")[-20:]:
                if line:
                    print("      " + line)
    else:
        print("    no server log for %s under %s" % (dbname, logdir))


def restart_services():
    """Start the run from a known state.

    A run that was killed can leave a csql session holding a transaction on
    demodb, a cub_server that stopdb never managed to stop, or monitoring files
    that no longer match their meta. None of that is repaired by deleting
    directories, so the suite bounces the whole service first.
    """
    cubrid_home = os.environ["CUBRID"]
    cubrid_bin = os.path.join(cubrid_home, "bin", "cubrid")
    print("restarting the CUBRID service to start from a known state ...")
    run_service_cmd([cubrid_bin, "service", "stop"], "service stop")
    reset_mon_data(cubrid_home)
    run_service_cmd([cubrid_bin, "service", "start"], "service start")
    # demodb is what most of the cases run against; "service start" only starts
    # it when cubrid.conf lists it, so ask for it explicitly.
    run_service_cmd([cubrid_bin, "server", "start", "demodb"],
                    "server start demodb")
    # And check that it really came up. Everything after this assumes it did:
    # the monitoring gather only registers volumes while the database is up, so
    # a silent failure here turns into a two minute wait and five failed cases
    # much later, where the cause is no longer visible.
    deadline = time.time() + 60
    while time.time() < deadline and not demodb_is_up():
        time.sleep(1)
    if not demodb_is_up():
        print("\033[31mdemodb did not start; run 'cubrid server start demodb' "
              "by hand to see why.\033[0m")
    wait_for_manager()


def stop_services():
    """Leave the host with the service down, the way the run found it.

    restart_services() brings the whole service up at the start, so a finished
    run would otherwise leave cub_manager, the brokers and cub_server demodb
    behind on a machine that was idle before. Runs from the finally block, so a
    failed or interrupted run stops them too.
    """
    cubrid_bin = os.path.join(os.environ["CUBRID"], "bin", "cubrid")
    print("stopping the CUBRID service ...")
    run_service_cmd([cubrid_bin, "service", "stop"], "service stop")


def init_env():
    response = do_one_job("login", case_path("login"), "", record_files=False)
    if response["status"] == "failure":
        request = load_task(case_path("login"))
        if not sys.stdin.isatty():
            # Asking for a password with nothing attached to stdin would wait
            # for an answer that cannot come; in CI that shows up as a job that
            # hangs until it is cancelled rather than as a failed login.
            print("login as %s failed (%s), and there is no terminal to ask "
                  "for a password on. Fix the credentials in %s."
                  % (request.get("id"), response.get("note", ""),
                     case_path("login")))
            sys.exit(1)
        request["password"] = getpass(
            "Please input the passwd for %s: " % (request["id"]))
        response = send_one("login", request, "")
        if response["status"] == "failure":
            print("login failed, cannot run the tests.")
            sys.exit(1)
    token = response["token"]
    response = do_one_job("getenv", case_path("getenv"), token,
                          record_files=False)
    return token, response["CUBRID"], response["CUBRID_DATABASES"]


# Command line:
#   test_tasks.py [<test set>] [-fc|--file-check] [-ns|--no-sleep]
#   test_tasks.py --dump <case> [<case> ...]
#
# <test set> is the list file of the set to run, "task_status_check.txt" by
# default. A bare name is looked up under task_test_case/.
#
# --file-check judges every case by comparing its response with the .answer
# file stored next to the case, instead of by the status field.
#
# --answer regenerates those .answer files. Nothing else writes them: adopting
# today's response as tomorrow's baseline has to be asked for.
#
# --no-sleep drops the "sleep <seconds>" lines of the list. They are there for
# servers whose tasks answer before their work is done; against one that does
# not, they are only lost time.
#
# Both take the CUBRID version the baseline belongs to, "11.4" or "11_4", as a
# bare argument; without one, DEFAULT_VERSION is used. The same request answers
# differently across engines, so a baseline is only meaningful next to the
# version it was taken from.
#
# A case listed as "<case>,<status>" is status only in every mode -- it gets no
# baseline and --file-check judges it by the status it declares.
#
# --dump logs in and prints the raw response of the named cases instead of
# running a list. It is a probe, so it uses the server as it finds it and never
# restarts anything.
args = sys.argv[1:]
dump_mode = bool(args) and args[0] == "--dump"
file_check = False
make_answer = False
no_sleep = False
listarg = DEFAULT_TEST_SET
VERSION = DEFAULT_VERSION

if not dump_mode:
    rest = []
    for arg in args:
        if arg in ("-fc", "--file-check"):
            file_check = True
        elif arg in ("-a", "--answer"):
            make_answer = True
        elif arg in ("-ns", "--no-sleep"):
            no_sleep = True
        elif arg.startswith("-"):
            print("unknown option: %s" % arg)
            sys.exit(2)
        elif normalize_version(arg):
            # A bare "11.4" is the version of the baseline, not a test set: a
            # set is named by a list file and those end in .txt.
            VERSION = normalize_version(arg)
        else:
            rest.append(arg)
    if len(rest) > 1:
        print("only one test set can be run at a time: %s" % " ".join(rest))
        sys.exit(2)
    if rest:
        listarg = rest[0]
    if VERSION not in KNOWN_VERSIONS:
        print("unknown version %s; known ones are %s"
              % (VERSION.replace("_", "."),
                 ", ".join(v.replace("_", ".") for v in KNOWN_VERSIONS)))
        sys.exit(2)
    if file_check and make_answer:
        print("--file-check compares against the baseline, --answer replaces "
              "it; pick one")
        sys.exit(2)

LIST_FILE, CASE_DIR, REPORT_BASE = resolve_test_set(listarg)
HOSTNAME = socket.gethostname()
local_env = REPORT_BASE not in NO_LOCAL_ENV_SETS

if not dump_mode:
    if not os.path.isfile(LIST_FILE):
        print("no such test set: %s" % LIST_FILE)
        sys.exit(2)
    if not os.path.isdir(CASE_DIR):
        print("no case directory for the set: %s" % CASE_DIR)
        sys.exit(2)
    if local_env:
        reset_leftovers()
        restart_services()
    else:
        # The login in init_env() is the reachability check: exec_task() reports
        # a manager that does not answer and stops the run there.
        print("%s runs against the instance as it is; skipping the local "
              "fixture setup and the CUBRID service bounce." % REPORT_BASE)

token, CUBRID, CUBRID_DATABASES = init_env()
# The calls above only set up the session, the report covers the task list.
results = []

if dump_mode:
    for name in args[1:]:
        print("===== %s =====" % name)
        dump_one(name, token)
    sys.exit(0)

# A plain "kill" skips the finally below, so make the helper processes go away
# on the usual termination signals as well.
atexit.register(stop_kill_targets)
for _signum in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(_signum, lambda signum, frame: sys.exit(128 + signum))

try:
    if local_env:
        build_env()
    do_all_jobs(token)
finally:
    if local_env:
        clean_env()
        stop_services()

# The reports are named after the test set, so running both sets leaves both
# reports behind instead of one overwriting the other.
xmlfile = os.path.join("log", REPORT_BASE + ".xml")
write_junit_xml(xmlfile)
write_junit_xml(detail_xml_path(xmlfile), with_response=True)

if file_check or make_answer:
    print("\n\033[33mbaselines: %s\033[0m" % answer_dir())

nstatus = sum(1 for r in results if r.get("status_only"))
if nstatus:
    print("\n\033[33m%d request(s) are marked status only in %s.\033[0m"
          % (nstatus, os.path.basename(LIST_FILE)))

nfailed = sum(1 for r in results if not r["ok"])
if nfailed:
    print("\n\033[31m%d of %d task(s) failed.\033[0m" % (nfailed, len(results)))
    for item in results:
        if not item["ok"]:
            print("  \033[31m%s\033[0m (%s): %s"
                  % (item["name"], item["file"], item["note"]))
    sys.exit(1)

print("\n\033[32mall %d tasks succeeded.\033[0m" % len(results))
