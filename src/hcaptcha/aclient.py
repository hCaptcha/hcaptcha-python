from json import JSONDecodeError

import httpx

from ._base import _BaseClient
from .result import VerificationResult


class HCaptchaAsyncClient(_BaseClient):
    """An asynchronous client for validating hCaptcha tokens."""

    def __init__(
        self,
        sitekey: str,
        secret: str,
        *,
        session: httpx.AsyncClient | None = None,
        api_base_url: str | None = None,
        threshold: float | None = None,
    ):
        super().__init__(
            sitekey, secret, api_base_url=api_base_url, threshold=threshold
        )
        if session is not None and not isinstance(session, httpx.AsyncClient):
            raise TypeError("session must be an httpx.AsyncClient")
        self._session = session or httpx.AsyncClient()

    async def verify(self, response: str | None = None, **kwargs) -> VerificationResult:
        """
        Asynchronously validates the hCaptcha token provided by the user.

        Args:
            response: The token received from the client side.
            kwargs: Extra parameters to pass to the client, ex. remoteip.

        Returns:
            VerificationResult: Check `success` for token validity and `raw`
            for the full API response.
        """
        return await self._do_verify(self._verify_url, response, **kwargs)

    async def verify_nojs(self, **kwargs) -> VerificationResult:
        """
        Asynchronously validates a No-JS hCaptcha request.

        This flow does not accept a response token. Only request data is sent.
        """
        return await self._do_verify(self._nojs_url, None, **kwargs)

    async def _do_verify(
        self, url: str, response_token: str | None, **kwargs
    ) -> VerificationResult:
        data = self._prepare_data(response_token, **kwargs)

        try:
            res = await self._session.post(url, data=data)
            res.raise_for_status()
            return VerificationResult.from_response(res.json(), self.threshold)
        except (httpx.HTTPError, JSONDecodeError) as exc:
            return VerificationResult.from_error(exc)
