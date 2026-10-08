# SentinelShield — Phase 1

SentinelShield is an **educational, rule-based WAF/IDS prototype** for a cybersecurity practical. It inspects a simplified HTTP request, identifies a small set of common web-attack indicators, and returns an allow/block decision with an explainable alert list.

> Important: this is not a production WAF. It does not replace input validation, authentication, secure coding, patching, monitoring, or a maintained WAF. The rules are intentionally compact and may produce false positives or miss evasive attacks.

## Phase 1 outcomes

- Clean, modular Python package
- Inspection of URL path, query parameters, headers, and request body
- One-pass URL and HTML-entity normalization before inspection
- Detection rules for SQL injection, cross-site scripting (XSS), directory traversal, local file inclusion (LFI), command injection, and sensitive-path probing
- Severity-aware allow/block decision
- Local SQLite security-event logging
- In-memory request-rate and login-burst detection
- Safe, offline unit tests using inert example strings

## Project layout

```
sentinelshield/
  models.py       # request, finding, verdict data structures
  rules.py        # detection patterns and rule evaluation
  engine.py       # inspection orchestration and decision policy
  cli.py          # small command-line demonstration
  events.py       # local SQLite event storage
  service.py      # inspection + event-recording workflow
  api.py          # local FastAPI integration layer
dashboard.py       # Streamlit event dashboard
tests/
  test_engine.py  # normal and malicious sample requests
  test_events.py  # database logging test
```

## Run it

Requires Python 3.10+; no third-party packages are needed.

```powershell
python -m unittest discover -s tests -v
python -m sentinelshield.cli
python -m sentinelshield.evaluation
python -m sentinelshield.reporting
python -m sentinelshield.simulation
```

You can also use one concise command entry point:

```powershell
python -m sentinelshield --help
python -m sentinelshield simulate
python -m sentinelshield evaluate
python -m sentinelshield export
python -m sentinelshield verify
```

For the dashboard and API, install the optional application dependencies:

```powershell
python -m pip install -r requirements.txt
```

Expected test result:

```
Ran 9 tests in ...s
OK
```

The demonstration prints one JSON verdict for each sample request and saves it in
`sentinelshield_events.db`. A normal search request is allowed; the example
attack-shaped inputs are blocked and include their matching rule IDs.

## Evaluate detection decisions

Run the controlled, offline evaluation dataset:

```powershell
python -m sentinelshield.evaluation
```

It reports true positives (TP), true negatives (TN), false positives (FP), false
negatives (FN), precision, recall, and F1 score. The included samples are designed
to test the current rules, so their results must be presented as a repeatable
classroom baseline—not a real-world detection-accuracy claim.

## Export security-event evidence

After events have been recorded, export the latest 100 records to a
spreadsheet-ready CSV file:

```powershell
python -m sentinelshield.reporting
```

The default output is `reports/sentinelshield-events.csv`. To choose a different
location, provide `--output`, for example:

```powershell
python -m sentinelshield.reporting --output reports/demo-events.csv
```

## Create safe demonstration events

Run a repeatable set of three normal and six attack-shaped offline scenarios:

```powershell
python -m sentinelshield.simulation
```

The simulator writes its decisions to the same SQLite database used by the
dashboard and CSV exporter. It does not send any network traffic or execute input.

## View the dashboard

After running the command-line demonstration at least once, install the dashboard
dependency and start it:

```powershell
python -m pip install -r requirements.txt
streamlit run dashboard.py
```

Streamlit will show a local browser address (usually `http://localhost:8501`). The
dashboard summarizes allowed versus blocked events, rule categories, and the most
recent saved events. It includes decision/category filters, expandable finding
details, and the local audit-chain status. Its live request inspector can create
and record a demonstration request directly from the browser. The dashboard reads
the same local SQLite database and does not transmit the event data anywhere.

## Use the local API

Install dependencies, then start the local service:

```powershell
python -m pip install -r requirements.txt
python -m uvicorn sentinelshield.api:app --reload
```

Open `http://127.0.0.1:8000/docs` for interactive API documentation. Use
`GET /health` to check the service, `POST /inspect` to inspect and store a request,
`POST /auth/result` to record a trusted authentication outcome, and `GET /events`
to retrieve recent events. `POST /auth/result` allows SentinelShield to identify
repeated confirmed failures; this is stronger evidence than a login-request burst.

For this learning API, `source_ip` is client-provided demonstration data. In a real
deployment, it must come from a trusted reverse proxy or application server.

## Run a protected demo application

This local FastAPI example uses SentinelShield as inbound middleware, rather than
submitting a manually constructed request to the API:

```powershell
python -m uvicorn sentinelshield.demo_app:app --reload
```

Try a normal request in your browser at `http://127.0.0.1:8000/search?q=campus`.
For a safe local detection demonstration, use
`http://127.0.0.1:8000/search?q=7%20OR%201%3D1`; the middleware should return
HTTP 403 with an explainable verdict and save the event. Do not expose this demo
application to the public internet.

## Configuration

The project uses sensible local defaults, but these environment variables can
override them before running the CLI, API, or dashboard:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SS_DATABASE_PATH` | `sentinelshield_events.db` | SQLite event database location. |
| `SS_BLOCK_SEVERITY` | `HIGH` | Lowest severity that causes a block. |
| `SS_RATE_WINDOW_SECONDS` | `60` | Time window for request counting. |
| `SS_REQUEST_LIMIT` | `20` | Maximum requests per source within the window. |
| `SS_LOGIN_LIMIT` | `5` | Maximum `/login` attempts per source within the window. |
| `SS_MAX_FIELD_LENGTH` | `4096` | Maximum characters inspected per individual request field. |

Example for the current PowerShell window:

```powershell
$env:SS_REQUEST_LIMIT = "10"
python -m sentinelshield.cli
```

## Decision policy

| Highest finding severity | Default decision |
| --- | --- |
| Critical or High | Block |
| Medium or Low | Allow and alert |
| No findings | Allow |

This policy is deliberately visible in `sentinelshield/engine.py` so it can be changed and discussed in a practical viva.

## Architecture

```
HTTP-like request
        |
        v
  request fields combined
        |
        v
  independent detection rules ----> findings (category, severity, evidence)
        |
        v
    decision policy ----> verdict (allow/block + alerts)
```

## Practical notes

- Rules look for indicators, not proof of exploitation.
- Evidence is truncated before it is returned to avoid overly large logs.
- The engine performs one layer of URL and HTML-entity decoding before matching;
  deeper or evasive encoding remains a documented limitation.
- Oversized fields are blocked after the configured limit. This limits inspection
  work but does not replace web-server request-size limits in a deployment.
- Event timestamps are UTC and findings are stored as JSON inside the local SQLite database.
- Newly stored events are linked with a SHA-256 audit chain. The verification
  command can reveal later database edits, but it is not immutable storage: an
  attacker who can rewrite the whole database can also recalculate the chain.
- Rate limits are per-process and reset when the program restarts. Login bursts indicate repeated attempts only; they do not prove failed authentication or brute force.
- The samples are strings only; the project does not send requests or execute payloads.
- Later phases can add structured event logging, SQLite storage, rate-limit detection, a dashboard, metrics, and a broader test corpus.

## Documentation

- [Architecture and security decisions](docs/ARCHITECTURE.md)
- [Step-by-step demonstration guide](docs/DEMONSTRATION_GUIDE.md)
- [Internship report draft](docs/INTERNSHIP_REPORT_DRAFT.md)
- [Contribution and quality guidelines](CONTRIBUTING.md)

## Continuous integration

The included GitHub Actions workflow runs the automated test suite on Python 3.10
and 3.11 whenever the project is pushed to a GitHub repository or a pull request
is opened.

## Optional Docker deployment

If Docker Desktop is installed, start the local API and dashboard together:

```powershell
docker compose up --build
```

Then open `http://127.0.0.1:8000/docs` for the API and
`http://127.0.0.1:8501` for the dashboard. Both services share a Docker volume for
the SQLite event database. Stop the stack with `Ctrl + C`; use
`docker compose down` when you want to remove the containers while preserving the
named event-data volume.
