# test_tasks.py 실패 분석

`task_list.txt` 전체를 로컬 CUBRID 11.5 + 실행 중인 CMS(admin/admin)에서 돌린 결과를
분석한 문서다.

- 최초 실패: **43건** / 193 케이스
- 테스트 케이스 문제를 고친 뒤: **19건**
- 재확인 요청 항목(트리거 `;`, compactdb 전용 DB, renamedb advanced off)을 반영한 뒤:
  **14건 / 196 케이스** (연속 2회 실행 결과 동일 — 재현 가능)
- CMS를 현재 소스에서 새로 빌드하고(보안 강화 커밋 포함) `dbmtuserlogin` 수정을 적용한
  서버로 다시 돌린 뒤: **10건 / 196 케이스**.
- 환경 제약 항목을 HA를 제외하고 모두 해소한 뒤: **2건 / 199 케이스**
  (연속 2회 동일 — 재현 가능). 남은 2건은 HA 미구성 케이스뿐이다.

즉 **서버 버그 4건은 해소**되었고, 새 빌드에서 드러난 테스트 케이스 문제 3건
(`runscript`, `backupdb_rep`, `updateuser_nopasswd`)도 고쳤으며(**6장**),
환경 제약으로 분류했던 8건도 HA 2건만 남기고 모두 통과시켰다(**5장**).
`renamedb` advanced on 경로도 실제로는 정상이며, 전용 DB로 커버리지를 복구했다(**7장**).

검증 환경(최초): `CUBRID 11.5.0 (11.5.0.2405-a2c3e03)`, non-HA, shard 미구성,
`support_mon_statistic=NO`.
검증 환경(현재): `CUBRID 11.5.0 (11.5.0.2441-6ba9522)` + 현재 소스에서 빌드한
`cub_manager`(`a2393c2` 보안 강화, `90e82a2` 포함), `support_mon_statistic=YES`,
non-HA는 그대로.

---

## 1. 서버 버그 (확인됨)

테스트 케이스는 정상인데 서버/유틸리티가 실패시키는 항목. CMS 소스 수정이 필요하다.

> **현재 상태(재검증 완료)** — 실행 중인 `cub_manager`(08-14 빌드)에는 1-1 수정이 들어가
> 있다. 바이너리에 `SET{t.g.name}`과 `SET{t.g}` 두 문자열이 모두 있으므로 버전 분기가
> 추가된 것으로 보인다. 그 결과 `dbmtuserlogin` + 연쇄 3건(1-2)은 **모두 success**다.
> 단, 이 저장소의 소스(`cm_job_task.cpp:10173`)에는 아직 반영돼 있지 않다.
> 1-3(트리거 `;`)은 새 바이너리에도 **반영되지 않았다** — 포맷 문자열이
> `create trigger\t%s\n` / `drop trigger\t%s\n` 그대로여서 테스트 측 `;` 우회가 여전히
> 필요하다.

### 1-1. `dbmtuserlogin` — db_user 조회 SQL이 CUBRID 11.5와 비호환 (재확인 완료: 버그 확정)

- 증상: `t.g is a varchar type, not an object type.`
- 원인: `cmd_dbmt_user_login()`(`server/src/cm_job_task.cpp:10173`)의 검증 쿼리가
  `db_user.groups`를 **객체 집합**으로 가정해 `SET{t.g.name}`을 쓴다.

  ```sql
  -- 현재 (실패)
  ... COALESCE(SUM(SET{t.g.name}), SET{}) from db_user u, TABLE(groups) AS t(g) ...
  -- 수정안 (csql로 동작 확인)
  ... COALESCE(SUM(SET{t.g}),      SET{}) from db_user u, TABLE(groups) AS t(g) ...
  ```

#### 재확인 결과 — "실제 서버 정보를 읽어 정상 분기된다"는 지적에 대해

코드에 분기가 있는 것은 맞지만, **분기 지점이 모두 SQL 실행 이후**라서 이 오류를 막지
못한다. 분기는 두 곳이다.

1. `run_csql_statement()`(`cm_job_task.cpp:10562`) — `uDatabaseMode()`로 실제 DB 상태를
   읽어 `--SA-mode` / `--CS-mode`를 골라 붙인다. 즉 "실제 서버 정보를 읽어 분기"하는 것은
   **csql 실행 모드**뿐이고, SQL 문자열은 건드리지 않는다.
2. `dbmt_user_is_dba()`(`cm_job_task.cpp:10106`) — `dbuser`가 `DBA`면 파일을 읽지 않고
   바로 1을 반환한다. 하지만 이 호출은 `run_csql_statement()`가 `ERR_NO_ERROR`를 준
   **다음**(`cm_job_task.cpp:10204`)이라, SQL이 깨지면 도달하지 못한다.

문제의 SQL은 `const char *statement`로 **버전 분기 없이 하드코딩**돼 있다.
(`cubrid_version_major/minor`, `CUBRID_VERS()` 분기 인프라는 있으나 이 쿼리에는 적용 안 됨.)

증거 4가지:

- **csql 직접 실행**: `t.g.name` → 파싱 오류, `t.g` → `count(*) = 1` 정상.
- **11.5의 `db_user` 스키마**: `db_attribute`에서 `groups`는 `SET`이고
  `domain_class_name`이 `NULL`(= 객체 집합 아님).
- **`db_user`가 클래스가 아니라 뷰**이고, 뷰 정의 자체가 groups를 이름 집합으로 평탄화한다:

  ```sql
  -- db_vclass.vclass_def (발췌)
  (SELECT COALESCE(SUM(SET{[g].[name]}), SET{}) FROM TABLE([u].[groups]) AS [t]([g]))
      AS [groups]
  ... FROM [_db_user] AS [u]
  ```

  즉 `.name` 조회는 기반 테이블 `_db_user`에서만 유효하다. CMS 쿼리는 `db_user`가
  뷰로 바뀌기 전 스키마를 기준으로 작성된 것이다.
  (`_db_user`로 바꾸는 건 답이 아니다 — 비 DBA는 `_db_user`를 못 읽으므로 이 검사의
  목적 자체가 깨진다.)
- **설치된 바이너리도 동일**: `$CUBRID/bin/cub_manager`(11.5.0.2405) 안에 같은
  `SET{t.g.name}` 문자열이 그대로 들어 있고, 실행 중인 CMS에 요청하면 재현된다.

  ```
  $ python3 test_tasks.py --dump dbmtuserlogin
  "note": "... t.g is a varchar type, not an object type.<end>",
  "status": "failure"
  ```

- 조치: `SET{t.g}`로 수정. CMS는 엔진 10.x 이상을 지원하므로(`cm_cmd_exec.cpp:213`),
  10.x에서 `db_user`가 아직 클래스라면 `CUBRID_VERS()` 분기가 필요하다 — 이 부분만
  엔진 10.x 환경에서 추가 확인이 필요하다.
- 영향(연쇄): dbmtuserlogin이 실패하면 demodb의 DBA 접속정보가 등록되지 않아,
  demodb에 DBA 권한이 필요한 아래 케이스가 함께 실패한다 → **1-2 참고**.

### 1-2. `createuser` / `updateuser` / `deleteuser` — 1-1의 연쇄

- 증상:
  - `createuser`, `deleteuser`: `Operation "add_user"/"drop_user" can only be performed by the DBA ...`
  - `updateuser`: `User "yifan" is invalid.` (선행 createuser 실패로 yifan 미생성)
- 원인: 이 task들은 `conlist`에 저장된 demodb 접속정보(사용자/비밀번호)로 CSQL을 실행하는데,
  그 정보는 `dbmtuserlogin`이 등록한다. 1-1로 등록이 안 되면 비 DBA로 접속돼 권한 오류가 난다.
- 확인: `dbmtuserlogin`(실패) 직후 `createuser`를 직접 호출 → 동일하게 "must be DBA"로 실패.
- 조치: 1-1을 고치면 함께 해소될 것으로 판단.

### 1-3. `addtrigger` / `altertrigger` / `droptrigger` — 생성 SQL에 문장 종료자 누락

- 증상: `Syntax error: unexpected 'commit', expecting ';'`
- 원인: `op_make_triggerinput_file_add/alter/drop()`
  (`server/src/cm_job_task.cpp:13506`, `13595`, `13568`)이 만드는 DDL이 **`;` 종료자 없이**
  곧바로 `commit;`을 붙인다. `alter`는 status와 priority가 둘 다 오면 두 개의
  `alter trigger` 문을 구분자 없이 연달아 쓰기까지 한다.
- 서버 수정안: 각 생성 함수에서 문장 끝에 `;`를 출력.
- **테스트 측 우회(적용 완료)**: 요청대로 각 케이스의 **마지막으로 출력되는 값**에 `;`를
  붙였다. 생성 순서상 그 값 뒤가 곧바로 `commit;`이므로 문장이 정상 종료된다.

  | 케이스 | 수정한 필드 | 생성되는 마지막 줄 |
  | --- | --- | --- |
  | `addtrigger` | `"action":"REJECT;"` | `execute	REJECT;` |
  | `altertrigger` | `"status":"INACTIVE;"`, `"priority":"00.00;"` | `alter trigger example status INACTIVE; alter trigger example priority 00.00;` |
  | `droptrigger` | `"triggername":"example;"` | `drop trigger	example;` |

  `droptrigger`는 필드가 `triggername` 하나뿐이라 그쪽에 붙일 수밖에 없다.
  이 우회는 **서버 버그를 감추는 것이 아니라 우회**하는 것이므로, 서버가 `;`를 붙이도록
  고치면 이 `;`들을 되돌려야 한다. 의도는 `task_list.txt`에 주석으로 남겼다.
- 결과: `addtrigger` / `altertrigger` / `droptrigger` 모두 success.

---

## 2. 재확인으로 해소된 항목

### 2-1. `compactdb` — 전용 DB를 만들어 실행하도록 변경 (해소)

- 기존 증상: `status=failure`인데 `note`에 compactdb 정상 진행 로그가 담김.
- 기존 원인: `compactdb`가 `alatestdb`를 대상으로 하는데, 그 DB는 같은 목록에서
  `addvoldb` → `backupdb` → `optimizedb` → `stopdb` → `loaddb` → `restoredb`를
  모두 거친 상태였다. 즉 앞선 태스크들의 상태에 오염된 DB를 대상으로 했다.
- 확인: 새로 만든 빈 DB(정지 상태)에 유틸리티를 직접 실행하면 정상이다 —
  `cubrid compactdb --verbose --SA-mode <newdb>` → exit 0, stderr 없음.
  따라서 `ts_compactdb()`의 stdout/stderr 처리 자체는 문제가 아니었다.
- 조치(적용 완료): 요청대로 compactdb 전용 DB를 쓰도록 분리했다.

  ```
  createdb_for_compactdb   # compactdbtest 생성
  compactdb                # dbname: compactdbtest
  deletedb_for_compactdb   # compactdbtest 제거
  ```
- 결과: 3건 모두 success.

### 2-2. `renamedb` — advanced off로 테스트 (해소)

- 기존 증상: `File ".../tmp/DBMT_task_..." does not have enough entries: 3 entries expected.`
  (오류 문자열은 CMS가 아니라 `cubrid renamedb` 유틸리티가 낸다)
- 기존 원인: advanced 모드에서 `tsRenameDB()`가 `"%d %s %s\n"`(index, from, to) 형식으로
  맵 파일을 쓰는데 `cubrid renamedb -i <map>`이 기대하는 형식과 어긋난다.
  → **advanced on 경로는 여전히 미해결이며, 별도 확인이 필요하다.**
- 조치(적용 완료): 요청대로 `renamedb.txt`를 `advanced:"off"`, `exvolpath:"none"`으로
  바꾸고 `volume` 매핑을 제거했다. 실패를 기대하는 3개 케이스
  (`renamedb_nullrename`, `renamedb_adoff`, `renamedb_erropen`)는 `destinationdb`가
  아직 존재해야 하므로 **성공 케이스보다 앞으로** 옮겼다.
- 뒷정리: renamedb는 `destinationdb`를 `anotherdb`로 바꾸므로,
  `deletedb_for_renamedb`(dbname `anotherdb`)를 추가해 등록정보까지 정리한다.
  이게 없으면 다음 실행에서 `anotherdb`가 이미 존재해 실패한다.
- 결과: `renamedb` success, 실패 기대 3건도 기대대로 failure, `deletedb_for_renamedb` success.

---

## 3. 테스트 로그 개선 (적용 완료)

같은 task를 여러 케이스가 공유해서(`renamedb`, `renamedb_adoff`, `renamedb_nullrename`,
`renamedb_erropen`이 모두 task `renamedb`) 로그만 보고는 어느 케이스가 깨졌는지 알 수
없었다. `test_tasks.py`를 다음과 같이 고쳤다.

- 한 줄의 맨 앞이 **케이스(파일) 이름**, 대괄호 안이 실제 task 이름이 되도록 변경.

  ```
  renamedb_adoff [renamedb] : failure
  compactdb [compactdb] : success
  ```
- 실패한 줄 아래에 **케이스 파일 경로**를 함께 출력.

  ```
  dbmtuserlogin [dbmtuserlogin] : expected success, got failure (...)
      case file: task_test_case_json/dbmtuserlogin.txt
  ```
- 실행 끝에 실패 목록을 케이스 이름 + 파일 경로 + note로 요약 출력.
- JUnit XML의 `<testcase>`에 `file="..."` 속성 추가.

### 실행 반복 가능성

`reset_test_dbs()`를 추가해, 실행 전/후에 **테스트가 만든 DB만**
(`alatestdb`, `compactdbtest`, `destinationdb`, `anotherdb`, `copydb`, `destinationdb1`,
`renameadvdb`, `renamedadvdb`) 디렉터리와 `databases.txt` 등록정보를 함께 정리한다.
`demodb`는 대상이 아니다. 기존 `clean_env()`는 디렉터리만 지우고 `databases.txt` 항목을
남겨서, 중간에 죽은 실행이 다음 실행을 깨뜨렸다(이번에 실제로 `destinationdb` 잔여 항목을
발견).

여기에 더해 `stop_test_servers()`를 붙였다. 디렉터리를 지워도 살아남는 `cub_server <db>`
프로세스가 다음 실행을 통째로 망가뜨리기 때문이다 → **10장**.

---

## 4. 고친 테스트 케이스 문제 (참고)

| 케이스 | 문제 | 조치 |
| --- | --- | --- |
| `createdb`, `createdb_for_copydb`, `createdb_fail_with_dup_name` | 서버가 필수로 요구하는 `charset` 누락 → `alatestdb` 생성 실패가 후속 ~15건으로 연쇄 | `"charset":"en_US"` 추가 |
| `viewlog`, `removelog` | 존재하지 않는 옛 로그 경로(`cub_js.access.log`) 참조 | viewlog는 실제 파일(`cub_manager.log`)로, removelog는 `build_env`가 만드는 일회용 파일로 변경 |
| `getfolderswithkeyword` | 존재하지 않는 `$CUBRID/tmp1` | `$CUBRID/tmp`로 수정 |
| `unloaddb` | `code`가 PUBLIC 소유라 CUBRID 11.5에서 `dba.code`로 해석돼 not found | `"classname":"public.code"`로 수정 |
| `optimizedb`(2번째, db-api 섹션) | 앞서 `deletedb`로 삭제된 `alatestdb`를 참조하는 중복 항목 | `task_list.txt`에서 주석 처리 |
| `addtrigger`, `altertrigger`, `droptrigger` | 서버가 `;`를 붙이지 않음 | 마지막 값에 `;` 추가 (1-3) |
| `compactdb` | 앞선 태스크로 오염된 `alatestdb` 사용 | 전용 DB 생성/삭제로 분리 (2-1) |
| `renamedb` | advanced on 경로가 맵 파일 형식 불일치로 실패 | `advanced:"off"`로 변경 + 뒷정리 추가 (2-2) |

`build_env()`에 removelog용 일회용 파일 생성 로직(`$CUBRID/tmp/test_removelog.log`)을 추가했다.

---

## 5. 환경 제약 / 비결정적 케이스 (8건 해소, HA 2건 잔존)

기존에 "환경 제약 10건"으로 분류했던 항목이다. HA 2건을 제외하고 **8건 모두 통과**하도록
만들었다. 아래는 각 항목의 최종 상태다.

| 케이스 | 최종 상태 | 근거 |
| --- | --- | --- |
| `changemode` | **미해결** | `The server was not configured for HA.` — HA 구성 필요 |
| `rolechange` | **미해결** | `'deact' command is invalid.` — HA 구성 필요 |
| `set_mon_interval` | 해소 | 5-1 |
| `get_mon_statistic` (16건 중 5건) | 해소 | 5-1, 5-2 |
| `killprocess` | 해소 | 5-3 |
| `killtransaction` | 해소 | 5-3 |

### 5-1. 모니터링 통계 — 설정 하나가 아니라 메타/rrd 불일치까지 겹쳐 있었다

`cm.conf`에 `support_mon_statistic YES`를 넣는 것으로 끝나지 않는다. 원인은 세 겹이다.

1. **수집 자체가 꺼져 있었다.** `mon_stat_init()`(`cm_server_interface.cpp:126`)은
   플래그와 무관하게 항상 호출돼 `meta.json`과 rrd 파일을 만든다. 반면 실제 수집
   `gather_mon_data()`는 `sco.iSupportMonStat == TRUE`일 때만 돈다
   (`cm_httpd.cpp:434`). 그래서 **파일은 있는데 내용이 비어 있는** 상태였고,
   `k_total_vol_num`이 0이라 `vol_mon` 파일 자체가 만들어지지 않았다.
2. **그 상태에서 `set_mon_interval`이 메타를 깨뜨린다.** `reset_meta()`
   (`cm_mon_stat.cpp:1627`)는 broker → DB → volume → os 순서로 파일을 하나씩 리사이즈하고
   **맨 마지막에** `K_INTERVAL`을 갱신한다. `vol_mon`이 없으므로 3번째 단계에서
   `get_rrdfile`이 실패하고 함수가 중단되는데, 이미 리사이즈된 broker/DB 파일은
   그대로 남는다. 결과적으로 **메타는 interval 60, 파일은 interval 80 크기**가 되어
   이후 모든 `set_mon_interval` 호출이 첫 단계에서 EOF로 실패한다(로그의
   `bufsize:[50500]` vs 실제 43300 ints).
3. **같은 불일치가 `get_mon_statistic`도 깨뜨렸다.** yearly 오프셋은
   `86400/interval + 30*24 = 2160`행부터 365행을 읽는데, 파일은 2165행뿐이라 EOF가 난다
   (`db_io_read` yearly 1건이 여기 해당). 나머지 4건은 `vol_freespace`로,
   볼륨이 등록된 적이 없어 `Can't find dbname_vol[demodb] in meta[k_db_rrd]`였다.

조치(적용 완료):

- `cm.conf`에 `support_mon_statistic YES` 추가.
- 깨진 `meta.json` / rrd 파일을 지우고 CMS 재시작 → `mon_stat_init()`이 새로 만들고,
  첫 수집 주기에 `demodb`의 볼륨 3개가 `k_db_rrd["demodb_vol"]`에 등록된다.
- 이후 `set_mon_interval`은 성공하고, 4개 파일이 모두 interval 80 크기로 일관되게
  리사이즈된다(broker 173200 / db 164540 / os 86600 / vol 51960 bytes = 각각 2165행).
- `setsysparam_cmconf` 케이스가 `cm.conf`를 **하드코딩된 내용으로 덮어쓴다**는 점도
  발견했다. 그대로 두면 테스트가 자기 실행 중에 `support_mon_statistic`을 지워서
  다음 실행이 깨진다 → 케이스의 `confdata`에도 같은 줄을 넣었다.

> 서버 측 개선 여지: `reset_meta()`가 원자적이지 않아 중간 실패 시 메타/파일이 영구히
> 어긋난다. `k_total_vol_num == 0`이면 `vol_mon` 리사이즈를 건너뛰거나, 초기화 시점에
> 빈 `vol_mon`을 만들어 두는 편이 안전하다. → **9장**

### 5-2. `get_mon_statistic`의 `volname`은 등록된 볼륨 이름이어야 한다

수집이 켜지자 4건이 `Can't find volname[demodb]`로 바뀌었다. 메타에 등록되는 이름은
`dbspaceinfo`의 `spacename`, 즉 **데이터 볼륨의 전체 경로**다.

```json
"demodb_vol": {
  "/.../databases/demodb/demodb": 0, "demodb_lgat": 1, "demodb_lgar_t": 2
}
```

케이스의 `"volname":"demodb"`를 `"$CUBRID_DATABASES/demodb/demodb"`로 고쳐 16건 전부
success.

### 5-3. `killprocess` / `killtransaction` — 실행 시점에 대상을 직접 만든다

고정 값(pid `99999`, tranindex `2(+)`)은 어느 호스트에서도 맞지 않는다.
`test_tasks.py`에 실행 시점 치환을 추가했다.

- `build_env()` → `start_kill_targets()`가
  - `sleep 3600`을 띄워 그 pid를 `$TEST_KILL_PID`로,
  - `csql --CS-mode -u dba demodb`에 `;autocommit off` + `select`를 넣어 트랜잭션을
    열어 두고, `gettransactioninfo`로 그 pid의 항목을 찾아 tranindex를
    `$TEST_TRANINDEX`로 넣는다. 응답은 `"1(ACTIVE)"` 형식이므로 숫자만 뽑는다
    (`killtran --kill-transaction-index`는 순수 정수만 받는다).
- `replace_env_vars()`가 케이스 파일의 두 플레이스홀더를 치환하고,
  `clean_env()` → `stop_kill_targets()`가 남은 보조 프로세스를 정리한다.

---

## 6. 새 CMS 빌드에서 드러난 테스트 케이스 문제 (수정 완료)

`dbmtuserlogin`이 고쳐지고 보안 강화 커밋(`a2393c2` / `90e82a2`)이 들어간 빌드로 돌리자,
이전 실행에서는 보이지 않던 3건이 새로 실패했다. 셋 다 **서버 버그가 아니라 케이스가
낡은 것**이라 테스트 쪽에서 고쳤다.

### 6-1. `runscript` — `script_path`가 인가된 경로 밖

- 증상: `path is not authorized (allowed paths are $CUBRID, $CUBRID/databases): ls`
- 원인: `a2393c2`가 `ts_run_script()`에 `is_authorized_filename()` 검사를 추가했다
  (`cm_job_task.cpp:11522`, `cm_server_util.cpp:4198`). 케이스는 `script_path`로 `"ls"`를
  넘기는데, 상대 경로라 `$CUBRID` / `$CUBRID_DATABASES` 밑으로 해석되지 않아 거부된다.
- 조치: `build_env()`가 `$CUBRID/tmp/test_runscript.sh`(0755)를 만들고, 케이스가 그 경로를
  가리키도록 변경. `run_child()`가 스크립트를 직접 exec하므로 실행 권한과 shebang이 필요하다.

### 6-2. `backupdb_rep` — `safereplication`이 서버에서 제거됨

- 증상: `expected failure, got success`
- 원인: 이 케이스는 `backupdb`와 `safereplication:"y"` 하나만 다르고, 그 값 때문에 실패하는
  것을 기대했다. 예전 `ts_backupdb()`는 이 값이 `y`면
  ``--safe-page-id `repl_safe_page <db>` `` 를 인자로 덧붙였고, 백틱이 확장되지 않은 채
  `cubrid backupdb`에 전달돼 실패했다. `a2393c2`가 이 백틱 명령 삽입 경로를 제거해서
  이제 `safereplication` 키는 **아무 데서도 읽히지 않는다**(`ts_backupdb()`,
  `cm_job_task.cpp:4538`).
- 조치: 기대값을 success로 변경(`task_list.txt`). 같은 볼륨명으로 백업을 두 번 수행하는
  커버리지는 그대로 남는다.

### 6-3. `updateuser_nopasswd` — `userpass` 생략은 원래 정상

- 증상: `expected failure, got success`
- 원인: `ts_update_user()`(`cm_job_task.cpp:830`)는 `userpass`가 **있는데** 값이
  `__NULL__`이거나 빈 문자열일 때만 거부한다. 키 자체가 없으면 "비밀번호는 그대로 두고
  groups/authorization만 갱신"이 정상 동작이다.
- 이전 실행에서 이 케이스가 통과했던 것은 **우연**이다. 1-1 때문에 선행 `createuser`가
  실패해 `yifan`이 없었고, 그래서 `User "yifan" is invalid.`로 실패했을 뿐이다.
  1-1이 고쳐져 `yifan`이 실제로 생기자 갱신이 정상 성공한다.
- 조치: 기대값을 success로 변경(`task_list.txt`).

---

## 7. `renamedb` advanced on — 서버 버그가 아니었다 (2-2 정정)

2-2에서 "`tsRenameDB()`의 `"%d %s %s\n"` 맵 파일 형식이 `cubrid renamedb -i`와 불일치"라고
적었는데, **형식은 정확히 맞다.** 실제 원인은 케이스가 볼륨을 다 나열하지 않은 것이었다.

엔진 쪽 파서는 `logpb_next_where_path()`(`src/transaction/log_page_buffer.c:9332`)다.

```c
sprintf (format_string, "%%d %%%ds %%%ds", PATH_MAX - 1, PATH_MAX - 1);
if (fscanf (where_paths_fp, format_string, &from_volid, from_volname, to_volname) != 3)
  → ER_LOG_USER_FILE_WITHOUT_ENOUGH_ENTRIES  /* "%d entries expected" = num_perm_vols */
```

- 요구 형식은 `<volid> <from_fullvolname> <to_fullvolname>` — CMS가 쓰는 것과 동일하다.
- 단, **영구 볼륨 개수만큼, volid 순서대로** 있어야 한다. 부족하면
  `does not have enough entries: N entries expected`(N = `num_perm_vols`)가 난다.
  volid나 현재 경로가 어긋나면 `unordered entries`가 난다.
- 기존 케이스(`task_test_case/renamedb`)는 주 볼륨 하나만 매핑했다. 원래 실패 메시지의
  `3 entries expected`는 `destinationdb`가 `addvoldb`를 거쳐 영구 볼륨 3개였기 때문이다.

실증(적용 완료): 볼륨을 빠짐없이 매핑하니 advanced on이 그대로 성공한다.
영구 볼륨이 2개(`<db>`, `<db>_x001`)인 DB로 확인했고, 1개만 매핑하면
`2 entries expected`, 2개 모두 매핑하면 success.

커버리지 복구: 기존 `renamedb`(advanced off) 체인은 그대로 두고, 볼륨 구성이 확정적인
전용 DB로 advanced on 케이스를 추가했다.

```
createdb_for_renameadv   # renameadvdb 생성 (영구 볼륨 1개)
renamedb_advanced        # renameadvdb → renamedadvdb, advanced:"on"
deletedb_for_renameadv   # renamedadvdb 제거
```

> CMS 쪽에 남는 아쉬움: `tsRenameDB()`는 요청에 담긴 볼륨만 그대로 받아 적고, 대상 DB의
> 실제 영구 볼륨 목록과 대조하지 않는다. 누락되면 엔진의 저수준 메시지가 그대로 노출된다.
> → **9장**

---

## 8. 재현 방법

```sh
cd server/test
python3 test_tasks.py                      # 전체 실행, 실패는 빨간색 "expected ... got ..."
TEST_XML=log/result.xml python3 test_tasks.py   # JUnit XML 리포트

# 개별 확인 (실제 토큰으로 원본 응답 출력)
python3 test_tasks.py --dump dbmtuserlogin
```

---

## 9. 남은 서버 측 확인 과제

| 항목 | 상태 | 내용 |
| --- | --- | --- |
| 1-1 | 실행 서버 반영됨 / **소스 미반영** | `SET{t.g.name}` → `SET{t.g}`. 실행 중인 바이너리에는 두 쿼리가 모두 들어 있어 버전 분기가 된 것으로 보인다. 같은 수정을 이 저장소 소스(`cm_job_task.cpp:10173`)에도 반영해야 한다 |
| 1-3 | **미반영** | `op_make_triggerinput_file_add/alter/drop()`에서 문장 끝 `;` 출력. 새 빌드에도 안 들어갔음(포맷 문자열 확인). 고치면 테스트의 `;` 우회 되돌리기 |
| 2-2 / 7장 | **정정됨 — 서버 버그 아님** | 맵 파일 형식은 정확하다. 다만 `tsRenameDB()`가 요청의 볼륨 목록을 실제 영구 볼륨과 대조하지 않아, 누락 시 엔진의 저수준 메시지가 그대로 노출된다(개선 여지) |
| 5-1 | 신규 | `reset_meta()`가 원자적이지 않다. 중간 실패 시 rrd 파일은 새 interval 크기, `meta.json`은 옛 interval로 남아 `set_mon_interval` / `get_mon_statistic`이 영구히 깨진다. `k_total_vol_num == 0`이면 `vol_mon` 리사이즈를 건너뛰거나 초기화 때 빈 파일을 만들 것 |
| 5-1 | 신규 | 모니터링 메타에 등록된 DB/볼륨이 **삭제 후에도 남는다**. 테스트가 만든 임시 DB가 매 실행마다 누적돼 `db_mon` / `vol_mon`이 계속 커진다(정리 로직 없음) |
| 엔진 | 신규 | `ER_BO_CANNOT_CREATE_VOL` 메시지에 **초기화되지 않은 메모리가 찍힌다** → 아래 참고 |

### 9-1. `ER_BO_CANNOT_CREATE_VOL` — 포맷 인자 개수 불일치 (엔진 버그)

메시지 카탈로그(`msg/en_US.utf8/cubrid.msg:195`)는 인자를 **3개** 받는다.

```
123 Unable to create %1$s for database "%2$s". Please refer "%3$s" for additional information.
```

그런데 두 호출부가 **2개만 넘긴다.**

- `src/transaction/log_page_buffer.c:4704` — `er_set_with_oserror (..., ER_BO_CANNOT_CREATE_VOL, 2, volinfo_fullname, db_fullname)`
- `src/storage/file_io.c:2451` — `er_set_with_oserror (..., ER_BO_CANNOT_CREATE_VOL, 2, vol_label_p, db_full_name_p)`

(정상 호출부는 3개를 넘긴다: `src/storage/tde.c:345`, `src/transaction/boot_sr.c:1866`.)

그 결과 `%3$s`가 스택의 쓰레기 값을 읽어 **프로세스 메모리 내용이 그대로 로그와 API 응답에
노출된다.** 실제로 관찰된 문자열은 x86 기계어 바이트다.

```
renamedb Unable to create /.../renamedadvdb/renamedadvdb_vinf for database "/.../renamedadvdb".
Please refer "H^I^CH^E^@tHL^I^a^:^{^?^?^?H^M5F^(G" for additional information.... No such file or directory
```

파급:

- 정보 노출(프로세스 메모리) — 보안 관점에서도 수정 대상이다.
- 이 바이트가 `cub_manager.err`에 남으면 `loadaccesslog` 응답이 **유효한 UTF-8이 아니게 되어**
  JSON 디코딩이 깨진다. 로그는 실행마다 누적되므로 한 번 오염되면 이후 모든 실행에서
  `loadaccesslog`가 실패한다(실제로 재현됨).
- 테스트 측 대응: 러너가 `response.decode(errors="replace")`로 읽도록 했다. 서버 결함을
  덮는 게 아니라, 로그를 되돌려주는 task의 페이로드 때문에 **무관한 케이스가 실패하지
  않도록** 하는 것이다.

---

## 10. 검증 환경에 대한 주의

- **CMS는 샌드박스 밖에서 기동해야 한다.** 제한된 셸에서 `cubrid manager start`로 띄운
  CMS는 `stopdb`가 `cubrid server stop`을 실행해도 서버가 내려가지 않아
  `cmd_stop_server()`(`cm_cmd_exec.cpp:305`)가 30초를 다 쓰고 `execute timeout`을 낸다.
  같은 명령을 셸에서 직접 실행하면 1초면 끝난다. 제품 버그가 아니라 기동 환경 문제이며,
  일반 셸에서 재기동하면 `stopdb`는 4초 내에 성공한다.
- **`stopdb`가 실패하면 좀비 `cub_server`가 남는다.** 디렉터리를 지워도 프로세스는 살아
  있어서, 다음 실행이 `Database(...) is active state` / `Unable to mount disk volume`으로
  연쇄 실패한다. `reset_test_dbs()`에 `stop_test_servers()`를 추가해 테스트가 만든 DB의
  서버를 실행 전후에 정리하도록 했다.
- **중단된 실행은 dbmt 사용자 `yifan`을 남긴다.** `build_env()`에서 best-effort로
  `deletedbmtuser`를 먼저 호출해 다음 실행의 `adddbmtuser`가 깨지지 않도록 했다.

---

## 11. 중단된 실행에 대한 내성

`build_env()`까지만 돌고 중간에 죽은 실행이 무엇을 남기는지 실제로 죽여 가며 확인했다.

| 남는 것 | SIGTERM / 예외 / Ctrl-C | SIGKILL |
| --- | --- | --- |
| 열어 둔 트랜잭션(csql) | 정리됨 | **자동 정리됨** — 아래 참고 |
| 더미 프로세스(`sleep 3600`) | 정리됨 | **남는다** → pid 파일로 회수 |
| 테스트 DB 디렉터리 / `databases.txt` | 다음 실행이 정리 | 다음 실행이 정리 |
| 좀비 `cub_server` | 다음 실행이 정리 | 다음 실행이 정리 |
| dbmt 사용자 `yifan` | 다음 실행이 정리 | 다음 실행이 정리 |
| `loaddb` 입력 파일 | 영향 없음(전용 덤프 사용) | 영향 없음 |

### 11-1. 트랜잭션은 남지 않는다 (확인함)

csql은 `stdin=PIPE`로 띄운다. 부모가 SIGKILL로 죽으면 파이프가 닫히고 csql이 EOF를 받아
스스로 종료하며, 열려 있던 트랜잭션은 롤백된다. 실측:

```
--- before kill ---   1(ACTIVE)  DBA  ...  csql
--- after SIGKILL of parent ---   csql exited / There are no transactions
```

### 11-2. 더미 프로세스는 남는다 → pid 파일로 회수

`sleep 3600`은 부모와 무관하게 살아남아 최대 1시간 떠 있는다. `start_kill_targets()`가
`log/helper_pids`에 **pid와 커맨드라인을 함께** 기록하고, 다음 실행의
`sweep_stale_helpers()`가 `/proc/<pid>/cmdline`이 기록과 **정확히 일치할 때만** 죽인다
(pid 재사용으로 무관한 프로세스를 죽이지 않기 위해서다). 실측:

```
killing helper left over from an earlier run: 1349894 sleep 3600
```

정상 종료 경로도 보강했다. `atexit`에 `stop_kill_targets()`를 걸고 `SIGTERM`/`SIGHUP`을
`sys.exit()`로 바꿔, `finally`와 `atexit`이 모두 실행되게 했다. `build_env()`도 `try` 안으로
옮겨서, 그 안에서 예외가 나도 정리가 돈다.

### 11-3. 실행 시작 시 서비스 재시작

위의 개별 정리로도 못 고치는 상태(모니터링 메타 불일치 등)가 있어서, 전체 실행은
**서비스 재시작으로 시작**한다(`restart_services()`, `--dump` 모드는 제외).

```
cubrid service stop        # CMS·브로커·모든 DB 정지, 남은 클라이언트 정리
(mon_data/* 삭제)          # 정지 상태에서만 안전하게 지울 수 있다
cubrid service start
cubrid server start demodb # cubrid.conf에 없더라도 demodb는 반드시 올린다
→ cm_port가 응답할 때까지 대기
```

`mon_data`를 지우는 이유는 5-1에 적은 `reset_meta()` 비원자성 때문이다. 한 번 어긋난
메타/rrd는 스스로 복구되지 않으므로, 매 실행이 CMS에게 새로 만들게 한다.
이어서 `build_env()`가 `wait_for_mon_data()`로 **첫 수집이 끝날 때까지 기다린다**.
기다리지 않으면 `vol_mon`이 아직 없어 `set_mon_interval`이 실패하고, 그 실패가 다시
메타를 깨뜨린다.

### 11-4. `loaddb` 입력의 실행 간 결합 제거

`loaddb`(목록 83행)는 `delete_orignal_files:"y"`로 입력 파일을 **소비**하는데, 그 입력이
`demodb`의 덤프였고 그 덤프를 만드는 `unloaddb`는 목록 **136행**에 있었다. 즉 `loaddb`는
직전 실행이 남긴 파일을 읽고 있었고, 중간에 죽은 실행이 있으면 다음 실행이
`file does not exists: .../demodb_schema`로 깨졌다(실제로 재현됨).

`build_env()`가 `cubrid unloaddb --CS-mode -O $CUBRID/tmp --output-prefix test_loaddb demodb`로
**일회용 덤프**를 만들고 케이스가 그것을 가리키게 했다. `delete_orignal_files:"y"` 경로는
그대로 검증하면서, demodb의 원본은 건드리지 않는다.
