# 인증서 테스트 (`server/test/ssl_cert`)

CMS의 TLS 키쌍(`conf/cm_ssl_cert.crt`, `conf/cm_ssl_cert.key`)을 다루는
`server/src/cm_ssl_cert.cpp`의 테스트다(CBRD-27829). 기동 시 확인
(`cm_ssl_cert_ensure ()`)과 생성(`cm_ssl_cert_generate ()`)을 확인한다.

기동 시 확인은 디스크의 파일 상태로 판단하므로, 시나리오마다 conf 디렉터리를 만들고
`ssl_cert_driver`로 한 번 호출한 뒤 파일, 결과, 로그를 확인한다. CUBRID 빌드와
실행 중인 CMS가 필요 없다.

```sh
./run_ssl_cert_tests.sh                                          # 시스템 OpenSSL, g++
OPENSSL_DIR=../../external/openssl/linux_64 ./run_ssl_cert_tests.sh   # 다른 OpenSSL (include/, lib/libssl.a, lib/libcrypto.a)
CXX=clang++ ./run_ssl_cert_tests.sh                              # 다른 컴파일러
```

- Linux에서 실행한다. 입력을 만들고 결과를 확인하는 데 `openssl` 명령(3.0 이상)과 GNU coreutils(`stat -c`, `date -d`, `timeout`)를 쓴다.
- root가 아닌 사용자로 실행한다. root는 파일 권한과 무관하게 읽고 쓰므로, 권한 시나리오
  (읽을 수 없는 키, 쓸 수 없는 conf 디렉터리)는 root로 실행하면 건너뛴다(`SKIP`).
- driver가 빌드되지 않거나 확인이 하나라도 실패하면 0이 아닌 값으로 끝난다.
- PR마다 CI(`.github/workflows/check.yml`의 `unit-test` job)에서 `../unit/run_unit_tests.sh` 다음에 실행된다.

## 파일

| 파일 | 내용 |
| --- | --- |
| `run_ssl_cert_tests.sh` | driver를 빌드하고 시나리오를 실행 |
| `ssl_cert_driver.cpp` | `cm_ssl_cert.cpp`의 함수를 명령행에서 한 번 호출하고 결과를 출력 |
| `fault_inject.c` | `LD_PRELOAD`로 지정한 `rename ()`, `unlink ()`, 디렉터리 `fsync ()` 호출을 실패시키거나 순서를 기록하는 라이브러리. Windows에서 다른 프로그램이 파일을 열고 있을 때의 실패와, 교체 단계마다 디렉터리가 동기화되는지를 확인 (빌드할 수 없으면 해당 시나리오를 건너뜀) |
| `shipped/11.3/cm_ssl_cert.crt/.key` | release/11.3 이전에 배포한 RSA 1024 키쌍 |
| `shipped/develop/cm_ssl_cert_1024.crt/.key`, `cm_ssl_cert_2048.crt/.key` | develop에서 배포한 키쌍 |

`shipped/`의 파일은 이전 버전이 배포한 키쌍 그대로이며, 개인키는 이미 공개된 것이다.
배포 키 판정과 교체를 시험하는 입력으로만 쓰고 설치하지 않는다. 키를 공개키 SHA-256으로
판정하는 목록(`cm_ssl_cert.cpp`의 `shipped_keys`)과 같은 키인지도 첫 시나리오에서 확인한다.

## 시나리오

| 구분 | 확인하는 것 |
| --- | --- |
| 새 설치 | YES: 키쌍 생성, 일반 파일, 키 0600, 생성 인증서 항목(v3, RSA 2048, sha256WithRSAEncryption, CA:FALSE, keyUsage, serverAuth, SKI, SAN, 기본 subject, 자체서명, serial, 유효기간), 로그 지문과 `openssl` 지문 일치, `openssl verify`(localhost, 127.0.0.1, ::1, 호스트명, sslserver). 재시작하면 다시 생성하지 않음. NO: 기동하지 않고 조치 안내 |
| 업그레이드 | 11.3 일반 파일, develop 1024·2048 링크: 교체, 링크가 일반 파일이 됨, 남은 배포 키 파일 삭제. 대상이 없는 링크(YES 생성, NO 종료), 배포 키로 다시 서명한 인증서, 1024 키 + 2048 인증서(YES 교체, NO 종료), NO + 배포 키(경고 후 기동, 변경 없음) |
| 한 파일만 있음 | 키만 / 인증서만, 배포 키 / 아님, YES / NO: 종료, 남은 파일 유지, 없는 파일 안내. 남은 파일이 배포 키이면 그 안내 |
| 짝 불일치, 판정 실패 | 짝 불일치, 읽을 수 없는 키, 손상된 키, DER 인증서, passphrase 키(PKCS#8, 전통 형식, 입력을 기다리지 않음): YES, NO 모두 종료하고 파일 유지. 한 파일을 읽을 수 없고 다른 파일이 배포 키이면 YES 교체, NO 종료. conf 디렉터리에 쓸 수 없으면 종료하고 파일 유지. 경로가 디렉터리이면 종료 |
| 관리자 키쌍 | 관리자 키쌍 + 남은 배포 키 파일(YES: 남은 파일만 삭제, NO: 변경 없음), 배포 키가 아닌 같은 이름 파일은 유지, 중간 체인이 있는 CA 발급 인증서 유지, 배포 키로 받은 CA 발급 인증서는 교체하고 재발급 안내 |
| 교체 중단 복구 | 새 키를 넣기 전(YES, NO), 새 인증서를 넣기 전, 이전 키 정리 전, 임시 파일을 쓰는 중에 멈춘 상태: 이전 키쌍이 그대로 남고 작업 파일(`.tmp-*`, `.old-*`)이 지워짐. 키가 링크였으면 링크를 되돌린 뒤 교체. 형식이 다른 이름의 파일은 유지. 교체가 실패하고 되돌리기도 실패한 경우(`fault_inject.c`): 작업 파일이 남고 다음 기동에서 이전 키쌍으로 복구(최초 생성은 다시 생성). 되돌리기에 성공하면 아무것도 남지 않음 |
| TLS 보안 수준 | `OPENSSL_CONF`로 수준 1~3 지정. NO + RSA 1024 배포 키(11.3, develop 1024): 수준 1 경고 후 기동, 수준 2 종료하고 원인·조치 안내. YES + 11.3 키 수준 2: 교체 후 기동. NO + RSA 2048 배포 키 수준 2: 기동. 관리자 RSA 1024 키쌍 수준 2: 종료. 새 설치 수준 3: 생성 후 종료. 이 OpenSSL이 `OPENSSL_CONF`에서 TLS 보안 수준을 읽지 않으면 건너뜀 |
| ssl_cert_san | 기본 SAN에는 인터페이스 주소가 없음(loopback만). `SSL_CERT_SAN` 환경 변수로 driver에 넘긴 이름·주소가 추가되고 중복은 빠짐, `openssl verify`로 확인. 잘못된 항목은 빠지고 로그에 남음. 32개 초과분은 빠짐. 기존 키쌍은 유지되고, 자체서명 인증서이면 설정에 있는데 인증서에 없는 항목과 인증서에만 있는 이름(설정에서 뺀 주소, 이전 빌드의 인터페이스 주소)을 경고. SAN 없는 자체서명이나 CA 발급 인증서는 경고 없음. generate에도 적용 |
| 생성 | subject와 유효기간 반영, 링크가 일반 파일이 됨, `.bak`과 임시 파일이 남지 않음. 잘못된 국가 코드나 유효기간, 쓸 수 없는 conf 디렉터리는 실패하고 파일 유지 |

`cub_manager`의 기동 절차(`start_service ()`에서의 호출, stderr 메시지)와 `generatecert`(디버그 빌드 전용),
`getcmsenv` task는 실행 중인 CMS로 확인한다(`../README.md`).
