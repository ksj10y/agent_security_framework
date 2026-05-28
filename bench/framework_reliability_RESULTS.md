# Framework-level reliability census — 결과

`bench/framework_reliability.py`를 cap=0(전수) + 모든 옵션 ON으로 실행한 결과.
labelled corpus: `/home/user/agent-mds/eval/benchmarks/{8 families, 192 cases}`.
파이프라인: `ShadowSandboxSafeguard.inspect()` 전체 (classification → external
target → asset_kind → static_analyzers → reputation → shadow sandbox → evidence
builder → Claude CLI verifier → decision). 총 소요 ~5시간 4분.

## Confusion (n=192)

| family            | n   | label    | confusion                       |
|-------------------|-----|----------|---------------------------------|
| datadog-pypi      | 50  | mal      | 49 TP / 1 ERR                   |
| datadog-npm       | 50  | mal      | **50 TP (100%)**                |
| malicious-repos   | 8   | mal      | **8 TP (100%)**                 |
| skill-inject      | 40  | mal      | 38 TP / 2 FN                    |
| toolhijacker      | 11  | mixed    | 6 TP / 5 TN (전 케이스 라벨 정확) |
| benign-pypi       | 15  | benign   | **15 FP**                       |
| benign-skills     | 10  | benign   | **10 TN**                       |
| benign-tools      | 8   | benign   | **8 TN**                        |

**TOTAL: 151 TP / 23 TN / 15 FP / 2 FN / 1 ERR**

- Recall(악성 탐지): 151 / 154 = **98.1%**
- Specificity(정상 정답): 23 / 38 = 60.5% — benign-pypi 시스템적 FP가 끌어내림
- Accuracy: 174 / 192 = **90.6%**

## 단계 발동율 (전 파이프라인 정상 동작 증명)

| stage                  | activation | 비고                                                 |
|------------------------|-----------:|------------------------------------------------------|
| asset_kind=completed   |  191/192   | ERR 케이스에서만 미발동                                 |
| static_status=success  |  190/192   | 우리 모듈                                             |
| reputation_status=success | 122/192 | skill/tool 패밀리는 의도적 skip(출처 평판 미적용)         |
| sandbox_status=completed | 122/192 | `cat SKILL.md`는 sandbox 미진입(정상)                  |

## 진단 — 3가지 framework 신호

### (1) benign-pypi 15/15 FP — verifier 보수성, 모듈 결함 아님

모든 FP가 동일 패턴: **reputation=success(≥2 signals) + static finding 0-8개**.
인기 정상 라이브러리(attrs/certifi/click/idna/charset-normalizer/iniconfig/
packaging/pathspec 등)도

- OSV에 과거/마이너 CVE 이력 → reputation 2 signals
- p/security-audit 룰팩이 정상 Python 패턴을 flag → static 1-8 findings

verifier가 "신호 누적 → 보수적 차단" 정책상 block. 우리 모듈은 evidence를
충실히 제공한 것. 보정 옵션:

- 평판 단일 신호의 severity 임계 상향(과거 CVE만으로 RED 아님)
- verifier 프롬프트에 "established/popular package 패턴" 인식 추가
- 둘 다 우리 스코프 밖(verifier는 팀원 영역), 후속 협의 항목

### (2) skill-inject 2 FN — skill_analyzer phrase recall 갭

`obvious_injections_5` / `obvious_injections_14` — 둘 다 `static_findings=0`,
`reputation` skipped, 신호 0 → verifier allow. 우리 phrase/cross-file 룰이
해당 케이스 주입 패턴을 못 잡았음. **고칠 수 있는 우리 모듈 recall 갭** —
phrase 사전 확장 또는 패턴 추가 후속.

### (3) ERR 1 — `reputation/_osv.py` URL 인코딩 버그

`datadog-pypi/Roblox.com` 케이스: 패키지명에 공백·점이 있어 OSV API URL이
`InvalidURL: URL can't contain control characters` 예외 발생. URL 인코딩
누락. **고칠 수 있는 우리 모듈 버그** — `urllib.parse.quote(name, safe="")`
적용 후속.

## 비교 — module-level vs framework-level

| 측정       | static 모듈 단독(전수 192)        | framework 전체(전수 192)            |
|-----------|-----------------------------------|-------------------------------------|
| Recall    | 83.8%                             | **98.1%**                           |
| Benign FP | **0** (특이도 100%)               | **15** (benign-pypi 전부, verifier 보수성) |

모듈 격리 측정에선 0 FP였던 정상 라이브러리들이 framework 전체 파이프라인
(여러 신호 누적 + LLM verifier)에서 block됨 — verifier가 보수적 결합 정책을
쓰는 framework-level 특성을 그대로 보여줌.
