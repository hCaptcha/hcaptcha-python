from urllib.parse import parse_qs

import httpx
import pytest
import respx
from httpx import Response

from hcaptcha.client import HCaptchaClient

SITEKEY = "test-sitekey"
SECRET = "test-secret"


def _mock_verify(payload):
    return respx.post("https://api.hcaptcha.com/siteverify").mock(
        return_value=Response(200, json=payload)
    )


def _mock_nojs(payload):
    return respx.post("https://api.hcaptcha.com/siteverify-nojs").mock(
        return_value=Response(200, json=payload)
    )


def test_sync_verify_success():
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        _mock_verify({"success": True})
        result = client.verify("valid-token")
    assert result.success is True
    assert result.passed is True
    assert result.raw["success"] is True


def test_sync_verify_forwards_future_fields():
    # New server fields must pass through without a package update.
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        route = _mock_verify({"success": True})
        result = client.verify(
            "valid-token",
            remoteip="1.2.3.4",
            future_field="future-value",
            repeated_field=["first", "second"],
        )
    assert result.success is True
    assert parse_qs(route.calls.last.request.content.decode()) == {
        "secret": [SECRET],
        "sitekey": [SITEKEY],
        "response": ["valid-token"],
        "remoteip": ["1.2.3.4"],
        "future_field": ["future-value"],
        "repeated_field": ["first", "second"],
    }


def test_sync_verify_validates_and_sends_known_fields():
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        route = _mock_verify({"success": True})
        result = client.verify(
            "valid-token",
            max_age=60,
            client_tokens={"session": "session-token"},
            remoteip_strictness="high",
            client_tags=["login", "public-api"],
        )
    assert result.success is True
    assert parse_qs(route.calls.last.request.content.decode()) == {
        "secret": [SECRET],
        "sitekey": [SITEKEY],
        "response": ["valid-token"],
        "max_age": ["60"],
        "client_tokens": ['{"session":"session-token"}'],
        "remoteip_strictness": ["high"],
        "client_tags": ['["login","public-api"]'],
    }


def test_sync_verify_preserves_client_tokens_string():
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        route = _mock_verify({"success": True})
        client.verify("valid-token", client_tokens='{"session":"session-token"}')
    assert parse_qs(route.calls.last.request.content.decode())["client_tokens"] == [
        '{"session":"session-token"}'
    ]


def test_sync_verify_preserves_client_tags_string():
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        route = _mock_verify({"success": True})
        client.verify("valid-token", client_tags='["login"]')
    assert parse_qs(route.calls.last.request.content.decode())["client_tags"] == [
        '["login"]'
    ]


@pytest.mark.parametrize(
    ("kwargs", "exception"),
    [
        ({"remoteip": "not-an-ip"}, ValueError),
        ({"remoteip": 1}, TypeError),
        ({"max_age": 0}, ValueError),
        ({"max_age": -1}, ValueError),
        ({"max_age": True}, TypeError),
        ({"max_age": "60"}, TypeError),
        ({"client_tokens": []}, TypeError),
        ({"client_tokens": {"unsupported": {1}}}, TypeError),
        ({"remoteip_strictness": "strict"}, ValueError),
        ({"remoteip_strictness": 1}, TypeError),
        ({"client_tags": ["login", 1]}, TypeError),
        ({"client_tags": {"login"}}, TypeError),
        ({"sitekey": "other-sitekey"}, TypeError),
    ],
)
def test_sync_verify_rejects_invalid_request_data(kwargs, exception):
    # Invalid local input must fail before it can create an invalid request.
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with pytest.raises(exception):
        client.verify("token", **kwargs)


def test_sync_verify_rejects_invalid_client_configuration():
    with pytest.raises(ValueError, match="sitekey"):
        HCaptchaClient(sitekey="", secret=SECRET)


@pytest.mark.parametrize(
    ("threshold", "exception"),
    [
        ("0.5", TypeError),
        (True, TypeError),
        (-0.1, ValueError),
        (1.1, ValueError),
        (float("inf"), ValueError),
    ],
)
def test_sync_client_rejects_invalid_threshold(threshold, exception):
    with pytest.raises(exception, match="threshold"):
        HCaptchaClient(sitekey=SITEKEY, secret=SECRET, threshold=threshold)


@pytest.mark.asyncio
async def test_sync_client_rejects_async_session():
    async with httpx.AsyncClient() as session:
        with pytest.raises(TypeError, match=r"httpx\.Client"):
            HCaptchaClient(sitekey=SITEKEY, secret=SECRET, session=session)


def test_sync_verify_nojs_rejects_response_keyword():
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with pytest.raises(TypeError, match="response"):
        client.verify_nojs(response="token")


def test_sync_invalid_token_fails():
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        _mock_verify({"success": False})
        result = client.verify("invalid-token")
    assert result.success is False
    assert result.passed is False


def test_sync_http_error_is_reported():
    # A failed HTTP call must surface in the result, not crash the caller.
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        respx.post("https://api.hcaptcha.com/siteverify").mock(
            return_value=Response(500)
        )
        result = client.verify("token")
    assert result.success is False
    assert result.passed is False
    assert result.error is not None


def test_sync_invalid_json_is_reported():
    # A malformed API response must return an operational error, not raise.
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        respx.post("https://api.hcaptcha.com/siteverify").mock(
            return_value=Response(200, content=b"not-json")
        )
        result = client.verify("token")
    assert result.success is False
    assert result.passed is False
    assert result.error is not None


def test_threshold_blocks_high_score_but_token_stays_valid():
    # Customers must be able to distinguish "invalid token" from "blocked by score".
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET, threshold=0.5)
    with respx.mock:
        _mock_verify({"success": True, "score": 0.9})
        result = client.verify("token")
    assert result.success is True
    assert result.passed is False
    assert result.score == pytest.approx(0.9)


def test_sync_threshold_score_equal_passes():
    # Contract: passed is False only when score is strictly greater than threshold.
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET, threshold=0.5)
    with respx.mock:
        _mock_verify({"success": True, "score": 0.5})
        result = client.verify("token")
    assert result.passed is True


def test_sync_threshold_without_score_ignored():
    # A missing score must not apply the threshold.
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET, threshold=0.5)
    with respx.mock:
        _mock_verify({"success": True})
        result = client.verify("token")
    assert result.passed is True
    assert result.score is None


def test_response_content_is_exposed():
    # Customers analyze the API response: typed fields and the full raw payload.
    payload = {
        "success": True,
        "score": 0.2,
        "score_reason": ["behavior"],
        "error-codes": ["sitekey-mismatch"],
        "sitekey": SITEKEY,
        "hostname": "example.com",
        "challenge_ts": "2026-01-01T00:00:00Z",
    }
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        _mock_verify(payload)
        result = client.verify("token")
    assert result.score == pytest.approx(0.2)
    assert result.score_reason == ["behavior"]
    assert result.error_codes == ["sitekey-mismatch"]
    assert result.sitekey == SITEKEY
    assert result.hostname == "example.com"
    assert result.challenge_ts == "2026-01-01T00:00:00Z"
    assert result.raw == payload


def test_sync_verify_nojs_success():
    # NoJS flow has no token: the API returns a score, not a "response" field.
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        route = _mock_nojs({
            "success": True,
            "score": 0.1,
            "score_reason": ["BELOW_THRESHOLD"],
        })
        result = client.verify_nojs(remoteip="1.2.3.4")
    assert result.success is True
    assert result.passed is True
    assert result.score == pytest.approx(0.1)
    assert parse_qs(route.calls.last.request.content.decode()) == {
        "secret": [SECRET],
        "sitekey": [SITEKEY],
        "remoteip": ["1.2.3.4"],
    }


def test_nojs_response_exposes_ekey():
    # The NoJS post_verify flow needs the first response ekey for the second call.
    client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        _mock_nojs({"success": True, "ekey": "29794428-18b4-4da1-a0e1-0b15f095b1eb"})
        result = client.verify_nojs(remoteip="1.2.3.4")
    assert result.ekey == "29794428-18b4-4da1-a0e1-0b15f095b1eb"


def test_api_base_url():
    client = HCaptchaClient(
        sitekey=SITEKEY, secret=SECRET, api_base_url="https://hcaptcha.example.com"
    )
    with respx.mock:
        route = respx.post("https://hcaptcha.example.com/siteverify").mock(
            return_value=Response(200, json={"success": True})
        )
        result = client.verify("token")
    assert result.passed is True
    assert route.called


def test_sync_inject_session():
    with httpx.Client() as session:
        client = HCaptchaClient(sitekey=SITEKEY, secret=SECRET, session=session)
        with respx.mock:
            _mock_verify({"success": True})
            result = client.verify("valid-token")
        assert result.success is True
        assert result.passed is True
