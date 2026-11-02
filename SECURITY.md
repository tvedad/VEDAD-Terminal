# Security Policy

## Responsible use

Vedad Terminal aggregates **read-only lookups against free, public data sources**.
It is intended for authorized security research, education, incident response, and
defensive investigation.

By using this software you agree that:

- You will only investigate targets you own or are **explicitly authorized** to
  assess.
- You will comply with all applicable local, national, and international laws, and
  with the terms of service and rate limits of every upstream data provider.
- You will not use the platform to harass, stalk, dox, or otherwise harm
  individuals, nor to gain unauthorized access to systems.

The tools do not exploit vulnerabilities, submit credentials, or perform intrusive
scanning beyond lightweight TCP connect checks on common ports. Even so, some
lookups (port checks, subdomain enumeration, certificate queries) can be considered
reconnaissance in certain jurisdictions or engagements — obtain permission first.

The authors accept no liability for misuse. See the [MIT License](LICENSE) for the
full disclaimer of warranty and liability.

## Supported versions

This project is distributed from the `main` branch. Security fixes are applied to
`main`; there are no long-term support branches.

## Reporting a vulnerability

If you discover a security issue in the platform itself — for example a way to make
the server perform requests it should not (SSRF), a path-traversal in case handling,
or a cross-site scripting vector in the dashboard — please report it privately.

- Please do **not** open a public issue for security reports.
- Instead, contact the Vedad Security Team directly.

Include the affected endpoint or file, reproduction steps, and the impact. You can
expect an acknowledgement within a few days. Coordinated disclosure is appreciated —
please give a reasonable window for a fix before publishing details.
Use the shared _get(...) / _SESSION helpers so requests reuse the tuned
connection pool and TLS settings.

Register it in the TOOLS dict near the bottom of osint.py:

python
"example": {
    "fn": tool_example,
    "label": "Example Lookup",
    "accepts": ["domain"],          # one or more detected input types
    "desc": "What it does, in a sentence.",
},
Keep the key short and unique. accepts drives input-type detection and sidebar
filtering in the UI.

Run the self-test to confirm the registry still loads and your tool is counted:

bash
python server.py --selftest
Try it end to end:

bash
python server.py
curl "http://localhost:8080/api/run/example?q=example.com"
Coding conventions
Python: 4-space indentation, snake_case, standard-library first. Catch
Exception explicitly (no bare except:).

Prefer the standard library over new dependencies. If a tool genuinely needs an
optional package, import it lazily and degrade gracefully when it is absent.

Keep comments about why, not what. Do not commit editor, cache, or scratch
files — data/, cases/, and __pycache__/ are git-ignored for that reason.