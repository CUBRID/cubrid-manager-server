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

CMS는 IPv4로만 listen하므로 IPv6 표기는 API 테스트로 만들 수 없다. 실제 세션이 유지되거나
삭제되는지는 API 테스트 세트 `task_session_ip_check`가 확인한다(`../README.md` 4.10).

## 테스트 추가

1. 의존성이 없는 소스(시스템 헤더만 쓰는 것)를 대상으로 `test_<이름>.cpp`를 만든다.
   CUBRID 헤더나 `libcubridcs`가 필요한 코드는 여기서 빌드할 수 없다.
2. `run_unit_tests.sh`의 `tests` 배열에 `"test_<이름>:<대상 소스 ...>"`를 추가한다.
3. `main ()`은 실패가 있으면 0이 아닌 값을 돌려준다.
