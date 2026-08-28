import httpx
import pytest
import respx
from urllib.parse import parse_qs
from httpx import Response
from hcaptcha.aclient import HCaptchaAsyncClient

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

@pytest.mark.asyncio
async def test_async_verify_success():
    client = HCaptchaAsyncClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        _mock_verify({"success": True})
        result = await client.verify("valid-token")
    assert result.success is True
    assert result.passed is True

@pytest.mark.asyncio
async def test_async_threshold_blocks_high_score():
    client = HCaptchaAsyncClient(sitekey=SITEKEY, secret=SECRET, threshold=0.5)
    with respx.mock:
        _mock_verify({"success": True, "score": 0.9})
        result = await client.verify("token")
    assert result.success is True
    assert result.passed is False

@pytest.mark.asyncio
async def test_async_inject_session():
    async with httpx.AsyncClient() as session:
        client = HCaptchaAsyncClient(sitekey=SITEKEY, secret=SECRET, session=session)
        with respx.mock:
            _mock_verify({"success": True})
            result = await client.verify("valid-token")
        assert result.success is True
        assert result.passed is True


@pytest.mark.asyncio
async def test_async_client_rejects_sync_session():
    with httpx.Client() as session:
        with pytest.raises(TypeError, match="httpx.AsyncClient"):
            HCaptchaAsyncClient(sitekey=SITEKEY, secret=SECRET, session=session)


@pytest.mark.asyncio
async def test_async_verify_nojs_forwards_request_data_without_response():
    client = HCaptchaAsyncClient(sitekey=SITEKEY, secret=SECRET)
    with respx.mock:
        route = _mock_nojs({"success": True, "score": 0.1})
        result = await client.verify_nojs(remoteip="1.2.3.4")
    assert result.success is True
    assert parse_qs(route.calls.last.request.content.decode()) == {
        "secret": [SECRET],
        "sitekey": [SITEKEY],
        "remoteip": ["1.2.3.4"],
    }
