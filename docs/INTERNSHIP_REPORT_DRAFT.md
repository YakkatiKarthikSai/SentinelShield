# SentinelShield: Advanced Intrusion Detection and Web Protection System

## Internship Project Report Draft

**Student:** [Karthik Sai Yakkati]  
**College:** [Sastra Deemed University]
**Department:** [Cyber Security & Block Chain Technology]
**Internship organization:** [Zenith Byte]  
**Mentor:** [Mentor name]  
**Submission date:** [Date]

---

## Abstract

SentinelShield is an educational web-application firewall and intrusion-detection
prototype developed to inspect HTTP-like request data, identify common malicious
indicators, make an explainable allow-or-block decision, and record the resulting
security event. The prototype detects indicators associated with SQL injection,
cross-site scripting, directory traversal, local file inclusion, command
injection, and sensitive-path probing. It also includes request-rate monitoring, login-burst detection, and
tracking of repeated confirmed authentication failures when an integrated
application supplies login outcomes.

The system uses a modular Python architecture, local SQLite event storage, a
Streamlit dashboard, a FastAPI integration layer, and an automated test suite.
On a controlled offline evaluation set containing six attack-shaped and three
normal samples, the current rules produced six true positives, three true
negatives, zero false positives, and zero false negatives. These figures validate
the implementation against the included baseline only; they do not establish
real-world WAF accuracy.

## 1. Introduction

Web applications commonly process untrusted input through URL paths, query
parameters, headers, and request bodies. Weak validation or unsafe handling of
this input can expose applications to attacks such as SQL injection and XSS.
SentinelShield was built as a practical learning system that shows how defensive
inspection, severity classification, event logging, and monitoring can be combined
in an explainable workflow.

## 2. Objectives

1. Inspect simplified HTTP-like requests using modular, rule-based signatures.
2. Detect six categories of web-attack indicators.
3. Assign severity and make transparent allow/block decisions.
4. Detect high-volume request activity and suspicious authentication patterns.
5. Store events locally and display them through a dashboard.
6. Provide a local API for application integration.
7. Test the system and measure controlled-dataset performance.

## 3. Technology Stack

| Area | Technology |
| --- | --- |
| Language | Python 3.10+ |
| API | FastAPI and Uvicorn |
| Dashboard | Streamlit |
| Database | SQLite |
| Testing | Python `unittest` |
| Event export | Standard-library CSV module |

## 4. System Architecture

The system accepts a request from the command-line demo or a local API. The
inspection engine checks the path, query parameters, headers, and body against
defined signatures. It combines signature findings with abuse-detection findings,
then applies the configured decision policy. The service stores the final event in
SQLite. The dashboard and CSV exporter read the same event database.

The project also includes a small local FastAPI demo application protected by
SentinelShield middleware. This demonstrates an actual interception flow: permitted
requests are passed to the application, while matching requests receive an HTTP 403
response and are logged.

See [Architecture and security decisions](ARCHITECTURE.md) for the component and
request-flow diagrams.

## 5. Implemented Features

### 5.1 Rule-based request inspection

| Rule ID | Category | Default severity |
| --- | --- | --- |
| SS-1001 | SQL injection indicator | High |
| SS-1002 | Cross-site scripting indicator | High |
| SS-1003 | Directory traversal indicator | High |
| SS-1004 | Local file inclusion indicator | High |
| SS-1005 | Command injection indicator | Critical |
| SS-1006 | Sensitive path probing | High |

Every finding records the matching rule ID, category, severity, request location,
evidence snippet, and explanatory message.

### 5.2 Decision policy

Requests with a highest finding severity of High or Critical are blocked by default.
Low and Medium findings can be retained as alerts without blocking. The threshold
is configurable using the `SS_BLOCK_SEVERITY` environment variable.

### 5.3 Abuse detection

- Request-rate limit: default maximum of 20 requests per source in 60 seconds.
- Login-burst limit: default maximum of 5 `/login` requests per source in 60 seconds.
- Confirmed authentication-failure tracking: the API can receive actual login
  outcomes through `POST /auth/result`; repeated failures raise rule SS-2003.

### 5.4 Event monitoring and reporting

Inspection results are written to SQLite with a UTC timestamp, request method,
path, decision, reason, and findings. The Streamlit dashboard provides a decision
summary, category chart, filterable event table, and a live request inspector. The
inspector lets a user submit safe demonstration data through the dashboard and
immediately see the resulting allow/block decision and saved event. The export tool
produces a CSV file suitable for spreadsheet analysis.

## 6. Testing and Evaluation

The automated suite covers normal requests, the six rule categories, rate limits,
login patterns, configuration, event storage, CSV export, service workflow, and
metric calculations.

Run the tests with:

```powershell
python -m unittest discover -s tests -v
```

At the time of this report draft, the project contained 23 passing tests.

### Controlled evaluation result

| Metric | Result |
| --- | ---: |
| True positives | 6 |
| True negatives | 3 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 1.00 |
| Recall | 1.00 |
| F1 score | 1.00 |

The evaluation uses a small, controlled offline dataset. Because the samples were
selected to exercise the implemented rules, the result should be described as a
baseline validation rather than a real-world benchmark.

## 7. Demonstration Procedure

1. Run the test suite.
2. Run `python -m sentinelshield.simulation` to create safe sample events.
3. Run `python -m streamlit run dashboard.py` and capture dashboard screenshots.
4. Run `python -m uvicorn sentinelshield.api:app --reload`.
5. Open `http://127.0.0.1:8000/docs` and demonstrate `GET /health` and
   `POST /inspect`.
6. Export evidence using `python -m sentinelshield.reporting`.

## 8. Limitations

- The signatures are intentionally small and do not cover all attack variations.
- A matching signature is an indicator, not proof that exploitation succeeded.
- The rate limiter is in memory and resets on restart.
- SQLite is appropriate for a local prototype, not high-volume distributed logging.
- Client-provided source addresses in the learning API must not be trusted in a
  deployed system.
- The controlled dataset is too small to support a claim of production accuracy.

## 9. Future Enhancements

1. Integrate middleware with a real demo web application.
2. Support trusted reverse-proxy source addresses and persistent distributed rate
   limiting.
3. Add authenticated dashboard access and role-based permissions.
4. Introduce larger independent test datasets and error analysis.
5. Add alert notifications and centralized log forwarding.
6. Add rule tuning, rule versioning, and false-positive review workflow.
7. Containerize the API and dashboard for consistent local deployment.

## 10. Conclusion

SentinelShield demonstrates the key stages of a lightweight WAF/IDS workflow:
request inspection, explainable detection, severity-based response, event storage,
monitoring, reporting, and repeatable evaluation. Its main strength is its modular
and transparent implementation, which makes the security decisions understandable
for a practical or internship setting. The limitations documented in this report
define the work required to move from an educational prototype toward a deployable
security product.
