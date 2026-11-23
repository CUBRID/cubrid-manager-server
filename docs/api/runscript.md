# runscript

> **Debug builds only.** Release builds do not offer this task and answer
> `Undefined request - runscript`: a remote request that runs a program on the server, as the user
> CMS runs as (root in the official docker image), is left out of release builds like
> [generatecert](generatecert.md). Run the script on the server instead.

Run a script on the server as the user CMS runs as, and answer whether it succeeded. The output of
the script is not returned.

Only a script that nobody but the user CMS runs as and root can change is run:

- It must be a file directly under `$CUBRID/conf`, not in a subdirectory. The path is compared
  after symbolic links are resolved, so a link in `$CUBRID/conf` that points outside it is
  refused (`only a script directly under <dir> can be run`). The file the link points to is the
  one run.
- It must be a regular file (`the script is not a regular file`).
- On Linux:
  - The script and `$CUBRID/conf` must be owned by the user CMS runs as or by root
    (`the script must be owned by ...`, `the script directory must be owned by ...`).
  - Neither may be writable by the group or others (`the script must not be writable by the
    group or others`, `the script directory must not be writable by the group or others`).
    Whoever can write the directory could replace the script after it is checked.
  - The script must be executable (`the script is not executable`). A file created with
    `writeandsaveconf` or another task has no execute bit, and an existing
    executable file cannot be rewritten by a task, so a task alone cannot make a script that runs.
- On Windows only the directory is checked.
- The path must also pass the [File Access](README.md#file-access) checks, and only `LANG`, `TZ` and
  `CUBRID_TMP` can be passed with `envvar`.

Permissions required to run this task: ADMIN (debug builds only)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| script_path | path of the script, a file directly under `$CUBRID/conf` |
| envvar | `NAME=value`, an environment variable passed to the script only. Optional, may be repeated. `NAME` is one of `LANG`, `TZ`, `CUBRID_TMP` |

## Request Sample

```
{
  "task": "runscript",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "script_path": "$CUBRID/conf/test_runscript.sh",
  "envvar": "LANG=en_US.UTF-8"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failure. A script that exits with a status other than 0 is a failure |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
  "note": "none",
  "status": "success",
  "task": "runscript"
}
```
