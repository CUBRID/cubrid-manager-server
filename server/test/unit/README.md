# 단위 테스트 (`server/test/unit`)

CUBRID를 빌드하지 않고 g++만으로 빌드되는 서버 소스의 테스트다. API 테스트(`../test_tasks.py`)가
실행 중인 CMS로는 만들 수 없는 입력을 확인한다.

```sh
./run_unit_tests.sh              # g++
CXX=clang++ ./run_unit_tests.sh  # 다른 컴파일러
```

테스트가 하나라도 빌드되지 않거나 실패하면 0이 아닌 값으로 끝난다. PR마다
`.github/workflows/check.yml`의 `unit-test` job이 실행한다.

| 테스트 | 대상 | 확인하는 것 |
| --- | --- | --- |
| `test_session_ip` | `server/src/cm_session_ip.cpp` | `session_ip_check`의 주소 비교. 같은 주소의 다른 표기(IPv4-mapped IPv6, IPv6의 0 생략·대소문자, link-local의 scope)는 같은 주소, 다른 주소는 다른 주소, 해석할 수 없는 값은 알 수 없음. 모드(`off`/`log`/`enforce`)와 비교 결과별 처리(허용, 경고 후 허용, 거부) |
| `test_file_write` | `server/src/cm_task_file.cpp` | `writeandsaveconf`, `setsysparam`, `writeprivatedata`가 쓸 파일을 여는 방식과 `writeandsaveconf`가 백업(`.bak`)을 쓰는 방식(CBRD-27831). owner·group·others 실행 비트 중 하나라도 있는 기존 파일과 그런 파일을 가리키는 심볼릭 링크는 거부되고 내용과 모드가 그대로임, 실행 권한이 없는 기존 파일은 내용이 바뀌고(이어 쓰지 않고) 모드가 유지됨, 링크는 대상에 쓰임, 새 파일은 umask 0에서도 0644로 만들어짐, 열 수 없으면 거부 사유를 남기지 않음. 백업은 바이트 그대로 복사되고, 새 백업은 원본 모드에서 실행 비트를 뺀 모드(umask 0에서 0600→0600, 0755→0644), 기존 백업은 모드 유지, 실행 가능한 백업과 실행 파일을 가리키는 링크인 백업은 거부되고 그대로임, 원본이 없으면 백업을 만들지 않음. 미리 거르는 검사(`ut_is_executable_file`)는 실행 파일과 그 링크만 실행 파일로 보고 디렉터리·없는 파일은 아님. Windows에서 실행 파일로 보는 확장자(대소문자, 끝의 `.`·공백, 최종 경로 포함)와 아닌 이름 |
| `test_script_path` | `server/src/cm_task_file.cpp` | `runscript`가 실행할 수 있는 스크립트(CBRD-27831). `$CUBRID/conf` 역할의 디렉터리 바로 아래 파일만(같은 파일의 다른 표기, 디렉터리 안을 가리키는 링크 포함) 허용하고, 하위 디렉터리·바깥 파일·바깥이나 하위를 가리키는 링크·없는 파일·디렉터리·group/others 쓰기 가능·실행 권한 없음·다른 소유자(CMS 사용자를 다른 uid로 넘겨 확인, root로 실행하면 건너뜀), group/others 쓰기 가능하거나 다른 사용자 소유인 디렉터리를 사유별 문구로 거부. 허용하면 링크를 푼 실제 경로를 돌려줌 |
| `test_log_name` | `server/src/cm_log_name.cpp` | `getlogfileinfo`, `getloginfo`, `getdberrorlog`가 로그 파일을 인스턴스별로 구분하는 이름 규칙(CBRD-26446). 엔진이 만드는 로그 이름(access와 `.access.denied`, 그 백업, `_qr_rule.err`, CAS 로그)은 그 인스턴스의 것으로, 엔진이 쓰지 않는 `<b>.err`는 아닌 것으로(broker `<b>_<n>`을 요청했을 때 다른 broker의 CAS 오류 로그 `<b>_<n>.err`가 섞이지 않게), 이름이 그 인스턴스 이름으로 시작하는 다른 인스턴스(`<name>_...`, `<name>x...`)의 로그는 아닌 것으로 판정. SHARD=ON broker의 이름(`_<proxy>.access`, `_<proxy>_<shard>_<cas>.*`)과, broker `b`(SHARD=ON)와 `b_1_0`의 CAS 로그가 같은 이름이 되는 경우 SHARD 값으로 구분하는 것 |

API 테스트는 SHARD=OFF broker(`query_editor`)로만 돌므로 SHARD=ON의 로그 이름은 `test_log_name`이
확인한다(`../README.md` 4.11).

CMS는 IPv4로만 listen하므로 IPv6 표기는 API 테스트로 만들 수 없다. 실제 세션이 유지되거나
삭제되는지는 API 테스트 세트 `task_session_ip_check`가 확인한다(`../README.md` 4.10).

## 테스트 추가

1. 의존성이 없는 소스(시스템 헤더만 쓰는 것)를 대상으로 `test_<이름>.cpp`를 만든다.
   CUBRID 헤더나 `libcubridcs`가 필요한 코드는 여기서 빌드할 수 없다.
2. `run_unit_tests.sh`의 `tests` 배열에 `"test_<이름>:<대상 소스 ...>"`를 추가한다.
3. `main ()`은 실패가 있으면 0이 아닌 값을 돌려준다.
