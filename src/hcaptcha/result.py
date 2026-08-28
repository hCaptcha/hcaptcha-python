from dataclasses import dataclass, field


@dataclass
class VerificationResult:
    """Outcome of a `siteverify` or `siteverify-nojs` call.

    - `success`: the API `success` field. True when the token is valid and not expired.
    - `passed`: the client decision.
    - `score`: an optional API response field.
    - `error`: set when the HTTP call failed before a usable response.
    - `raw`: the full API response payload.
    """

    success: bool
    passed: bool
    score: float | None = None
    score_reason: list | None = None
    ekey: str | None = None
    error_codes: list | None = None
    sitekey: str | None = None
    hostname: str | None = None
    challenge_ts: str | None = None
    error: str | None = None
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_response(cls, payload: dict, threshold: float | None) -> "VerificationResult":
        success = bool(payload.get("success", False))
        score = payload.get("score")
        passed = success and not (
            score is not None and threshold is not None and score > threshold
        )
        return cls(
            success=success,
            passed=passed,
            score=score,
            score_reason=payload.get("score_reason"),
            ekey=payload.get("ekey"),
            error_codes=payload.get("error-codes"),
            sitekey=payload.get("sitekey"),
            hostname=payload.get("hostname"),
            challenge_ts=payload.get("challenge_ts"),
            raw=payload,
        )

    @classmethod
    def from_error(cls, error: BaseException) -> "VerificationResult":
        return cls(success=False, passed=False, error=str(error), raw={})
