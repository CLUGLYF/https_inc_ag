# Incident Agent

This service implements the `ga5-incident-agent/v2` API used by the incident-check task. It makes one model request for each new run, emits diagnostic dispatches, then advances only from submitted receipts. Run state and receipt replays are stored in SQLite.

## Deploy on Render

Create a Render Blueprint from this repository using `render.yaml`. The Blueprint uses a persistent disk mounted at `/var/data`, so the web service needs a paid Render instance that supports disks. Set `LLM_API_KEY` to a Google AI Studio API key when Render prompts for the unsynced environment variable. The configured endpoint is Google's OpenAI-compatible API and the default model is `gemini-2.5-flash`.

After deployment, submit the service's public HTTPS origin as the incident-agent base URL, without a path, query, or trailing slash. Do not add credentials to the URL. Keep the service on one worker: the state database and per-run locks are designed for this single-process deployment.

To configure the service manually, set:

| Variable | Value |
| --- | --- |
| `DB_PATH` | `/var/data/state.db` on a persistent Render disk |
| `LLM_BASE_URL` | `https://generativelanguage.googleapis.com/v1beta/openai` |
| `LLM_API_KEY` | Your private Google AI Studio API key |
| `LLM_MODEL` | `gemini-2.5-flash` |

Start command:

```sh
uvicorn app:app --host 0.0.0.0 --port $PORT --workers 1
```

Run the local syntax check with `python -m py_compile app.py`. `selftest.py` accepts a deployed base URL and exercises the remote API lifecycle.