import ipaddress
import json
import math


DEFAULT_API_BASE_URL = "https://api.hcaptcha.com"
_RESERVED_REQUEST_FIELDS = frozenset({"secret", "sitekey", "response"})


class _BaseClient:
    """Internal base class for hCaptcha clients."""

    def __init__(self, sitekey: str, secret: str, *, api_base_url: str | None = None, threshold: float | None = None):
        self.sitekey = self._validate_required_text("sitekey", sitekey)
        self.secret = self._validate_required_text("secret", secret)
        base_url = (api_base_url or DEFAULT_API_BASE_URL).rstrip("/")
        self._verify_url = f"{base_url}/siteverify"
        self._nojs_url = f"{base_url}/siteverify-nojs"
        self.threshold = self._validate_threshold(threshold)

    def _prepare_data(
        self, response_token: str | None = None, **kwargs: object
    ) -> dict[str, object]:

        data: dict[str, object] = {
            "secret": self.secret,
            "sitekey": self.sitekey,
        }

        for name, value in kwargs.items():
            if name in _RESERVED_REQUEST_FIELDS:
                raise TypeError(f"{name} is managed by the client")
            if name == "remoteip":
                self._validate_remoteip(value)
            elif name == "max_age":
                self._validate_positive_integer(name, value)
            elif name == "client_tokens":
                value = self._serialize_client_tokens(value)
            elif name == "remoteip_strictness":
                self._validate_remoteip_strictness(value)
            elif name == "client_tags":
                value = self._serialize_client_tags(value)
            data[name] = value

        if response_token is not None:
            data["response"] = self._validate_required_text(
                "response", response_token
            )

        return data

    @staticmethod
    def _validate_required_text(name: str, value: object) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value

    @staticmethod
    def _validate_remoteip(value: object) -> None:
        if not isinstance(value, str):
            raise TypeError("remoteip must be a string")
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("remoteip must be a valid IPv4 or IPv6 address") from exc

    @staticmethod
    def _validate_threshold(value: object) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("threshold must be a number or None")
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("threshold must be between 0 and 1")
        return float(value)

    @staticmethod
    def _validate_positive_integer(name: str, value: object) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
        if value <= 0:
            raise ValueError(f"{name} must be a positive integer")

    @staticmethod
    def _validate_remoteip_strictness(value: object) -> None:
        if not isinstance(value, str):
            raise TypeError("remoteip_strictness must be a string")
        if value not in {"off", "low", "high"}:
            raise ValueError("remoteip_strictness must be off, low, or high")

    @staticmethod
    def _serialize_client_tokens(value: object) -> str:
        if isinstance(value, str):
            return value
        if not isinstance(value, dict):
            raise TypeError("client_tokens must be a string or dictionary")
        try:
            return json.dumps(value, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                "client_tokens must be a JSON-serializable dictionary"
            ) from exc

    @staticmethod
    def _serialize_client_tags(value: object) -> str:
        if isinstance(value, str):
            return value
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise TypeError("client_tags must be a string or list of strings")
        return json.dumps(value, separators=(",", ":"))
