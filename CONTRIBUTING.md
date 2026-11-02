# Contributing

Thanks for your interest in improving OSINT Terminal. New **keyless** tools, bug
fixes, and documentation are all welcome.

## Ground rules

- **No API keys.** Every tool must work against a free, public source with no
  account, token, or paid tier required. Pull requests that add key-gated tools will
  be asked to switch to a keyless alternative.
- **Read-only.** Tools perform lookups, not attacks. No exploitation, credential
  submission, or intrusive scanning beyond lightweight TCP connect checks.
- **Fail soft.** A tool must never raise to the caller. On any error it returns a
  dict with an `"error"` key so one dead source never breaks the rest of the app.

## Project layout

| File         | What it holds                                                       |
|--------------|---------------------------------------------------------------------|
| `osint.py`   | All tool functions and the `TOOLS` registry.                        |
| `server.py`  | The stdlib HTTP server and JSON API.                                |
| `index.html` | The single-page dashboard (vanilla JS/CSS).                         |

## Adding a tool

1. Write a function that takes a single query string and returns a JSON-serializable
   dict:

   ```python
   def tool_example(q):
       """One-line description of what this returns."""
       try:
           r = _get(f"https://api.example.com/lookup/{quote(q)}")
           data = r.json()
           return {"field": data["field"], "source": "example.com"}
       except Exception as e:
           return {"error": str(e)}
   ```

   Use the shared `_get(...)` / `_SESSION` helpers so requests reuse the tuned
   connection pool and TLS settings.

2. Register it in the `TOOLS` dict near the bottom of `osint.py`:

   ```python
   "example": {
       "fn": tool_example,
       "label": "Example Lookup",
       "accepts": ["domain"],          # one or more detected input types
       "desc": "What it does, in a sentence.",
   },
   ```

   Keep the key short and unique. `accepts` drives input-type detection and sidebar
   filtering in the UI.

3. Run the self-test to confirm the registry still loads and your tool is counted:

   ```bash
   python server.py --selftest
   ```

4. Try it end to end:

   ```bash
   python server.py
   curl "http://localhost:8080/api/run/example?q=example.com"
   ```

## Coding conventions

- Python: 4-space indentation, `snake_case`, standard-library first. Catch
  `Exception` explicitly (no bare `except:`).
- Prefer the standard library over new dependencies. If a tool genuinely needs an
  optional package, import it lazily and degrade gracefully when it is absent.
- Keep comments about *why*, not *what*. Do not commit editor, cache, or scratch
  files — `data/`, `cases/`, and `__pycache__/` are git-ignored for that reason.

## Pull requests

- Keep PRs focused; one feature or fix per PR.
- Describe the data source and confirm it is keyless.
- Make sure `python server.py --selftest` passes and the files compile
  (`python -m py_compile osint.py server.py`).

By contributing you agree that your contributions are licensed under the project's
[MIT License](LICENSE).
