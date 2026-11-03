<!-- pipelineguard-report -->
<!-- pipelineguard-commit:1111111111111111111111111111111111111111 -->
## ❌ PipelineGuard: FAIL

**demo/vulnerable-app** · `main` · `1111111111` · environment `production`

FAIL: PG-003 High findings; PG-006 Medium findings (environment: production, policy: default v1)

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| 0 | 5 | 3 | 2 | 0 |

### Rules triggered
- `PG-003` **High findings** (FAIL): 5 active high finding(s); policy allows at most 0.
- `PG-006` **Medium findings** (WARN): 3 active medium finding(s); warning threshold is 0.

### Top blocking-severity findings
- **HIGH** subprocess shell true (semgrep:scanner-config.pg.python.subprocess-shell-true) — `tests-data/vulnerable-app/app.py:10`
  - Remediation: subprocess call with shell=True can lead to OS command injection. Pass an argument list and omit shell=True.
- **HIGH** Image user should not be 'root' (trivy:DS-0002) — `Dockerfile:2`
  - Remediation: Add 'USER <non root user name>' line to the Dockerfile
- **HIGH** eval usage (semgrep:scanner-config.pg.python.eval-usage) — `tests-data/vulnerable-app/app.py:14`
  - Remediation: eval() on dynamic input allows arbitrary code execution. Use ast.literal_eval or a safe parser.
- **HIGH** sql string format (semgrep:scanner-config.pg.python.sql-string-format) — `tests-data/vulnerable-app/app.py:27`
  - Remediation: SQL built with string formatting is injectable. Use parameterized queries.
- **HIGH** 'apt-get' missing '--no-install-recommends' (trivy:DS-0029) — `Dockerfile:4`
  - Remediation: Add '--no-install-recommends' flag to 'apt-get'

<details><summary>Limitations</summary>

- Risk scores are a transparent heuristic; absent EPSS/KEV data is recorded as unknown, not as safe.

</details>

[Full report](http://127.0.0.1:8000/scans/e16d960c-4baf-457f-afb3-a60d87018100)