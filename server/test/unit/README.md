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
| `test_file_write` | `server/src/cm_task_file.cpp` | `writeandsaveconf`, `setsysparam`, `writeprivatedata`가 쓸 파일을 여는 방식과 파일을 복사하는 방식(`ut_copy_file`: `writeandsaveconf`의 백업 `.bak`, `copyfolder`의 각 파일)(CBRD-27831). owner·group·others 실행 비트 중 하나라도 있는 기존 파일과 그런 파일을 가리키는 심볼릭 링크는 거부되고 내용과 모드가 그대로임, 실행 권한이 없는 기존 파일은 내용이 바뀌고(이어 쓰지 않고) 모드가 유지됨, 링크는 대상에 쓰임, 새 파일은 umask 0에서도 0644로 만들어짐, 열 수 없으면 거부 사유를 남기지 않음. 복사는 바이트 그대로이고, 새 복사본은 원본 모드에서 실행 비트를 뺀 모드(umask 0에서 0600→0600, 0755→0644), 기존 대상은 모드 유지, 실행 가능한 대상과 실행 파일을 가리키는 링크인 대상은 거부되고 그대로임, 원본이 없으면 대상을 만들지 않음. 미리 거르는 검사(`ut_is_executable_file`)는 실행 파일과 그 링크만 실행 파일로 보고 디렉터리·없는 파일은 아님. Windows에서 실행 파일로 보는 확장자(대소문자, 끝의 `.`·공백, 최종 경로 포함)와 아닌 이름 |
| `test_script_path` | `server/src/cm_task_file.cpp` | `runscript`가 실행할 수 있는 스크립트(CBRD-27831). `$CUBRID/conf` 역할의 디렉터리 바로 아래 파일만(같은 파일의 다른 표기, 디렉터리 안을 가리키는 링크 포함) 허용하고, 하위 디렉터리·바깥 파일·바깥이나 하위를 가리키는 링크·없는 파일·디렉터리·group/others 쓰기 가능·실행 권한 없음·다른 소유자(CMS 사용자를 다른 uid로 넘겨 확인, root로 실행하면 건너뜀), group/others 쓰기 가능하거나 다른 사용자 소유인 디렉터리를 사유별 문구로 거부. 그 위의 상위 디렉터리도 group/others 쓰기 가능하면(바로 위든 더 위든) 그 디렉터리를 담은 문구로 거부하고, sticky bit가 있으면(`/tmp`, 01775) 허용. 다른 사용자 소유 상위 디렉터리는 root로 실행할 때만 확인(nobody로 chown). 허용하면 링크를 푼 실제 경로를 돌려줌 |
| `test_os_release` | `server/src/cm_os_release.cpp` | `getenv`의 `osinfo_detail`. `ut_utf8_char_len`: 2~4바이트 UTF-8, C1 제어 문자, overlong, surrogate, U+10FFFF 초과, 잘린 시퀀스. `ut_parse_os_release_value`: 따옴표 없는 값과 주석, `'...'`, `"..."`의 이스케이프(`\"` `\\` `\$` `` \` ``), 닫히지 않은 따옴표, 제어 문자·잘못된 UTF-8 제거, UTF-8 보존, 문자 경계에서 자르기. `ut_get_os_release_detail`: "NAME VERSION"과 VERSION이 없을 때의 폴백(PRETTY_NAME, "NAME VERSION_ID", NAME), 마지막 대입 우선, 너무 긴 줄 무시, 읽지 않는 파일(빈 파일, 디렉터리, FIFO, 크기 초과), `/usr/lib/os-release` 폴백(첫 파일이 없거나 깨진 링크일 때만) |
| `test_log_name` | `server/src/cm_log_name.cpp` | `getlogfileinfo`, `getloginfo`, `getdberrorlog`가 로그 파일을 인스턴스별로 구분하는 이름 규칙(CBRD-26446). 엔진이 만드는 로그 이름(access와 `.access.denied`, 그 백업, `_qr_rule.err`, CAS 로그)은 그 인스턴스의 것으로, 엔진이 쓰지 않는 `<b>.err`는 아닌 것으로(broker `<b>_<n>`을 요청했을 때 다른 broker의 CAS 오류 로그 `<b>_<n>.err`가 섞이지 않게), 이름이 그 인스턴스 이름으로 시작하는 다른 인스턴스(`<name>_...`, `<name>x...`)의 로그는 아닌 것으로 판정. SHARD=ON broker의 이름(`_<proxy>.access`, `_<proxy>_<shard>_<cas>.*`)과, broker `b`(SHARD=ON)와 `b_1_0`의 CAS 로그가 같은 이름이 되는 경우 SHARD 값으로 구분하는 것 |
| `test_smtp_client` | `server/src/cm_smtp_client.cpp` | CMS가 쓰던 jwSMTP (GPLv2)를 대신하는 SMTP 클라이언트 (CBRD-27830). base64 (RFC 4648 예제와 NUL이 든 바이트), 로그용 문자열 (`smtp_printable`: CR/LF/NUL/DEL/비ASCII는 `?`, 200자 넘으면 자르고 `...`), cm.conf `smtp_server` 형식 (`smtp_parse_server_address`: 호스트 이름, IPv4, `[IPv6]`, 포트 생략 시 25, 1~65535. `[]` 없는 IPv6, 닫히지 않은 `[`, scope가 붙은 IPv6, `[]` 안의 IPv4·이름, 공백, `_`, `-`로 시작·끝나는 label, 빈 label, 끝의 `.`, 숫자뿐인 잘못된 IPv4, 63자 넘는 label, 253자 넘는 이름은 호스트 오류. 빈 포트, 0, 65536 이상, 부호, 숫자가 아닌 포트는 포트 오류. 오류면 결과를 바꾸지 않음), 메일함 주소 (`user@host`, `name <user@host>`, 앞뒤 공백. 빈 값, `@` 앞뒤가 빈 주소, 공백, 닫히지 않은 `<`, `>` 뒤의 문자, CR/LF/NUL은 거부), 메시지 (UTC·동쪽·서쪽 (전날)·30분 단위 시간대의 Date, From/To/Subject, 비ASCII 이름은 주소만, 비ASCII 제목은 75자 이하이고 문자를 자르지 않는 UTF-8 encoded word, 줄바꿈이 든 제목 거부, 본문은 76자 이하 base64 줄이고 `.`만 있는 줄이 없으며 원문으로 복원됨). 루프백 포트의 가짜 서버 (자식 프로세스)로 발송: 인증 없음, 호스트 이름, AUTH LOGIN, AUTH LOGIN과 빈 비밀번호 (빈 줄로 응답), AUTH PLAIN, 인증 거부 (상세에 비밀번호 없음), EHLO 거부 시 HELO, 수신자 거부, 인사말 554, 인사말 뒤 연결 끊김, SMTP가 아닌 응답, 응답 없는 서버의 timeout (주어진 시간 안에), 한 바이트씩 천천히 보내는 응답도 응답 전체가 timeout 안에 끝남, 연결 거부, 이름 해석 실패, IPv6 (`::1`, 없으면 건너뜀). 잘못된 인자 (CR/LF를 넣은 수신자, 빈 발신자, 줄바꿈이 든 제목, NUL이 든 사용자 이름, 알 수 없는 인증 방식, 빈 호스트, 포트 0, timeout 0)는 접속하지 않고 거부 |

API 테스트는 SHARD=OFF broker(`query_editor`)로만 돌므로 SHARD=ON의 로그 이름은 `test_log_name`이
확인한다(`../README.md` 4.11).

CMS는 IPv4로만 listen하므로 IPv6 표기는 API 테스트로 만들 수 없다. 실제 세션이 유지되거나
삭제되는지는 API 테스트 세트 `task_session_ip_check`가 확인한다(`../README.md` 4.10).

API 테스트는 `osinfo_detail`을 테스트 호스트의 os-release 하나로만 비교하므로(`../README.md`), 그 파일로는
만들 수 없는 입력은 `test_os_release`가 입력 표로 확인한다.

## 테스트 추가

1. 의존성이 없는 소스(시스템 헤더만 쓰는 것)를 대상으로 `test_<이름>.cpp`를 만든다.
   CUBRID 헤더나 `libcubridcs`가 필요한 코드는 여기서 빌드할 수 없다.
2. `run_unit_tests.sh`의 `tests` 배열에 `"test_<이름>:<대상 소스 ...>"`를 추가한다.
3. `main ()`은 실패가 있으면 0이 아닌 값을 돌려준다.
