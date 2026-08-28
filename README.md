# hcaptcha-python

[![PyPI version](https://img.shields.io/pypi/v/hcaptcha-python.svg)](https://pypi.org/project/hcaptcha-python/)
[![Python versions](https://img.shields.io/pypi/pyversions/hcaptcha-python.svg)](https://pypi.org/project/hcaptcha-python/)
[![CI](https://github.com/hCaptcha/hcaptcha-python/actions/workflows/ci.yml/badge.svg)](https://github.com/hCaptcha/hcaptcha-python/actions/workflows/ci.yml)

## Overview

A minimal server-side Python client for validating hCaptcha tokens with
`siteverify`.

- Synchronous and asynchronous clients.
- Single dependency: `httpx`.
- Explicit imports: you must import the client you need.
- Explicit configuration: the client reads no environment variables. Framework
  wrappers own configuration sources and construct the client explicitly.
- Forward-compatible request fields: pass a new server field as a keyword argument. A package update is not required.

## Package Boundary

This package sends server-to-server verification requests. It does not render
the hCaptcha browser widget. It does not read web-framework configuration. It
does not extract tokens from HTTP requests. It does not protect routes.

Django, FastAPI, and Flask packages can build these integration features on
top of this client.

## Installation

```bash
pip install hcaptcha-python
```

Requires Python 3.11 or higher.

## Direct Verification

```python
from hcaptcha.client import HCaptchaClient

client = HCaptchaClient(sitekey="your-sitekey", secret="your-secret")
result = client.verify("user-response-token")

if result.success:
    # Continue with the protected operation.
    ...
```

Use a keyword argument for an optional request field.

## Development

Install the test tools and run all local checks:

```bash
pip install -e ".[test]"
ruff check .
mypy src
pytest -q --disable-warnings
python -m build
twine check dist/*
```

## Release

1. Update the package version and `CHANGELOG.md`.
2. Run the development checks.
3. Create a Git tag and GitHub Release with the exact package version. For example, use `1.0.0`, not `v1.0.0`.
4. Create the release from `main`.

The release workflow verifies the version, builds the source and wheel distributions, and publishes the checked artifacts to PyPI.

## Contribute

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open an issue or pull request.
For package support, read [SUPPORT.md](SUPPORT.md).

## Configuration

Both client constructors accept these parameters:

| Parameter      | Type | Default | Description |
|----------------|------|---------|-------------|
| `sitekey` | `str` | — | Required hCaptcha site key. |
| `secret` | `str` | — | Required hCaptcha secret key. Keep it on the server. |
| `session` | `httpx.Client` or `httpx.AsyncClient` | `None` | A caller-owned HTTP client. Use it to configure connection pooling, transport, and timeouts. The synchronous client requires `httpx.Client`. The asynchronous client requires `httpx.AsyncClient`. |
| `api_base_url` | `str \| None` | `None` | The API base URL. `None` uses `https://api.hcaptcha.com`. |
| `threshold` | Number from `0` to `1`, or `None` | `None` | Optional local risk cutoff. When hCaptcha returns a score greater than this value, `passed` is `False` while `success` keeps the API value. A score equal to the threshold passes. |

The client does not close a session that you provide. Close it in your
application lifecycle.

## Request Parameters

`verify()` takes a token and optional keyword request fields.

- `verify(response, remoteip="1.2.3.4")`

`verify_nojs()` accepts the same keyword request fields, but it does not accept
a response token. It is a feature that requires an hCaptcha Enterprise plan.

The client forwards new server fields unchanged without a package update. It
rejects `secret`, `sitekey`, and `response` as keyword fields because the
client owns these fields.

The client validates `remoteip` locally:

| Field | Python type | Behavior |
|---|---|---|
| `remoteip` | `str` | Recommended client IP address. Must be a valid IPv4 or IPv6 address. |

Enterprise-only request fields:

- `max_age`: See enterprise docs.
- `remoteip_strictness`: See enterprise docs.
- `client_tokens`: See enterprise docs.
- `client_tags`: See enterprise docs.

All additional request fields are documented in the official hCaptcha documentation: <https://docs.hcaptcha.com/>. For Enterprise fields, see <https://docs.hcaptcha.com/enterprise>.

## Operational Errors

`verify()` and `verify_nojs()` return a `VerificationResult` for all handled
HTTP, timeout, transport, and response-decoding failures. These failures set
`result.error`, set `result.success` to `False`, and set `result.raw` to an
empty dictionary.

A valid hCaptcha rejection is not an operational error. It returns
`result.success == False`, with the response data in `result.raw` and, when
provided, `result.error_codes`.

Check `result.error` before you act on a verification result:

```python
result = client.verify("user-response-token")

if result.error is not None:
    # Apply the application's failure policy.
    ...
elif not result.success:
    # hCaptcha rejected the token.
    ...
else:
    # Continue with the protected operation.
    ...
```

## `VerificationResult`

`verify()` returns a `VerificationResult`:

| Field | Type | Description |
|---|---|---|
| `success` | `bool` | The API `success` field. True when the token is valid and not expired. |
| `passed` | `bool` | The client decision. It is `False` when verification fails or the score is greater than `threshold`. |
| `score` | `float \| None` | The optional API risk score. |
| `score_reason` | `list \| None` | The optional API score reasons. |
| `ekey` | `str \| None` | The optional API ephemeral session identifier. |
| `error_codes` | `list \| None` | The API `error-codes` field. |
| `sitekey` | `str \| None` | The optional API sitekey field. |
| `hostname` | `str \| None` | The optional API hostname field. Do not use it for authentication. |
| `challenge_ts` | `str \| None` | The optional API challenge timestamp. |
| `error` | `str \| None` | Set when the HTTP call failed before a usable response. |
| `raw` | `dict` | The full API response payload. |

Use `raw` when your application needs other response fields.

## Additional Usage

### Synchronous

```python
from hcaptcha.client import HCaptchaClient

client = HCaptchaClient(sitekey="your-sitekey", secret="your-secret")
result = client.verify(
    "user-response-token",
    remoteip="1.2.3.4",
)

if result.success:
    ...
# analyze the response:
# result.success, result.error_codes, result.error, result.raw
```

### Asynchronous

```python
from hcaptcha.aclient import HCaptchaAsyncClient

client = HCaptchaAsyncClient(sitekey="your-sitekey", secret="your-secret")
result = await client.verify("user-response-token", remoteip="1.2.3.4")
```

### Session Injection

```python
import httpx
from hcaptcha.client import HCaptchaClient

with httpx.Client() as session:
    client = HCaptchaClient(sitekey="your-sitekey", secret="your-secret", session=session)
    result = client.verify("user-response-token")
```
