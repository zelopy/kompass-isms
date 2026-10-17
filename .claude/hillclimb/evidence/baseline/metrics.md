# 증적 검토 평가 결과

실행 16건 (오류 0건)

| 지표 | 값 |
|---|---|
| verified | 100.0% |
| first_try | 100.0% |
| leak_free | 100.0% |
| no_invented | 100.0% |
| style_ok | 100.0% |
| no_verdict | 100.0% |
| expected_gaps | 100.0% |
| gap_budget | 87.5% |
| no_field_names | 68.8% |

토큰: 입력 19,926, 출력 31,302, 비용 약 $0.72

## 메모

- ca01-1-roster#1: 필드 이름: - 점검 도구가 지정한 대상 리소스(targets)가 없어 대조 대상 계정 범위 확인 불가
- ca01-1-roster#2: 필드 이름: - 점검 도구가 지정한 확인 대상 리소스(targets) 없음으로 대조 대상 계정 범위 확인 필요
- ca09-1-injection#2: 필드 이름: 점검 도구가 지정한 대상 리소스(targets) 없음
- ca11-2-column-encryption#1: 필드 이름: 점검 도구가 지정한 확인 대상 리소스(targets) 없음으로 현황표의 DB가 어느 클라우드 DB 인스턴스인지 대응 확인 안 됨
- ca17-1-log-policy#1: 부족한 점이 상한(2개)보다 많음: CA-17-1
- ca17-1-log-policy#1: 필드 이름: - 점검 대상 리소스(targets) 미지정으로 지침과 실제 설정 간 대응 관계 확인 불가
- ca17-1-log-policy#2: 부족한 점이 상한(2개)보다 많음: CA-17-1
