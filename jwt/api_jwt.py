import json
from calendar import timegm
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Type, Union

from . import api_jws
from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    MissingRequiredClaimError,
)
from .types import DecodeOptions, JOSEHeader, JWTPayload


class PyJWT:
    def __init__(self, options: Optional[DecodeOptions] = None):
        if options is None:
            options = {}
        self.options = {**self._get_default_options(), **options}

    @staticmethod
    def _get_default_options() -> DecodeOptions:
        return {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "require": [],
        }

    def encode(
        self,
        payload: JWTPayload,
        key: str,
        algorithm: str = "HS256",
        headers: Optional[JOSEHeader] = None,
        json_encoder: Optional[Type[json.JSONEncoder]] = None,
    ) -> str:
        # Check that we get a mapping
        if not isinstance(payload, Mapping):
            raise TypeError(
                "Expecting a mapping object, as JWT only supports "
                "JSON objects as payloads."
            )

        # Payload
        payload = payload.copy()
        for time_claim in ["exp", "iat", "nbf"]:
            # Convert datetime to a intDate value in known time-format claims
            try:
                val = payload[time_claim]
            except KeyError:
                pass
            else:
                if isinstance(val, datetime):
                    payload[time_claim] = timegm(val.utctimetuple())

        json_payload = json.dumps(
            payload, separators=(",", ":"), cls=json_encoder
        ).encode("utf-8")

        return api_jws.encode(
            json_payload, key, algorithm, headers, json_encoder
        )

    def decode_complete(
        self,
        jwt: str,
        key: str = "",
        algorithms: Optional[List[str]] = None,
        options: Optional[DecodeOptions] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        if options is None:
            options = {"verify_signature": True}
        else:
            options.setdefault("verify_signature", True)

        if options["verify_signature"] and not algorithms:
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        decoded = api_jws.decode_complete(
            jwt,
            key=key,
            algorithms=algorithms,
            options=options,
            **kwargs,
        )

        try:
            payload = json.loads(decoded["payload"])
        except ValueError as e:
            raise DecodeError("Invalid payload string: %s" % e)
        if not isinstance(payload, dict):
            raise DecodeError("Invalid payload string: must be a json object")

        if options["verify_signature"]:
            merged_options = {**self.options, **options}
            self._validate_claims(payload, merged_options, **kwargs)

        decoded["payload"] = payload
        return decoded

    def decode(
        self,
        jwt: str,
        key: str = "",
        algorithms: Optional[List[str]] = None,
        options: Optional[DecodeOptions] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        decoded = self.decode_complete(jwt, key, algorithms, options, **kwargs)
        return decoded["payload"]

    def _validate_claims(
        self,
        payload: JWTPayload,
        options: DecodeOptions,
        audience: Optional[Union[str, List[str]]] = None,
        issuer: Optional[str] = None,
        leeway: Union[float, timedelta] = 0,
        **kwargs: Any,
    ) -> None:
        if isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()

        if not isinstance(audience, (bytes, str, type(None), Iterable)):
            raise TypeError("audience must be a string, iterable, or None")

        self._validate_required_claims(payload, options)

        now = timegm(datetime.utcnow().utctimetuple())

        if "iat" in payload and options["verify_iat"]:
            self._validate_iat(payload, now, leeway)

        if "nbf" in payload and options["verify_nbf"]:
            self._validate_nbf(payload, now, leeway)

        if "exp" in payload and options["verify_exp"]:
            self._validate_exp(payload, now, leeway)

        if options["verify_iss"]:
            self._validate_iss(payload, issuer)

        if options["verify_aud"]:
            self._validate_aud(payload, audience)

    def _validate_required_claims(
        self, payload: JWTPayload, options: DecodeOptions
    ) -> None:
        for claim in options["require"]:
            if payload.get(claim) is None:
                raise MissingRequiredClaimError(claim)

    def _validate_iat(
        self, payload: JWTPayload, now: float, leeway: float
    ) -> None:
        iat = payload["iat"]
        assert isinstance(iat, (str, int))
        try:
            int(iat)
        except ValueError:
            raise InvalidIssuedAtError(
                "Issued At claim (iat) must be an integer."
            )

    def _validate_nbf(
        self, payload: JWTPayload, now: float, leeway: float
    ) -> None:
        nbf = payload["nbf"]
        assert isinstance(nbf, (str, int))
        try:
            nbf = int(nbf)
        except ValueError:
            raise DecodeError("Not Before claim (nbf) must be an integer.")

        if nbf > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    def _validate_exp(
        self, payload: JWTPayload, now: float, leeway: float
    ) -> None:
        exp = payload["exp"]
        assert isinstance(exp, (str, int))
        try:
            exp = int(exp)
        except ValueError:
            raise DecodeError(
                "Expiration Time claim (exp) must be an" " integer."
            )

        if exp < (now - leeway):
            raise ExpiredSignatureError("Signature has expired")

    def _validate_aud(
        self, payload: JWTPayload, audience: Optional[Union[str, List[str]]]
    ) -> None:
        if audience is None and "aud" not in payload:
            return

        if audience is not None and "aud" not in payload:
            # Application specified an audience, but it could not be
            # verified since the token does not contain a claim.
            raise MissingRequiredClaimError("aud")

        if audience is None and "aud" in payload:
            # Application did not specify an audience, but
            # the token has the 'aud' claim
            raise InvalidAudienceError("Invalid audience")

        assert audience is not None
        audience_claims = payload["aud"]

        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(c, str) for c in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")

        if isinstance(audience, (bytes, str)):
            audience = [audience]

        if not any(aud in audience_claims for aud in audience):
            raise InvalidAudienceError("Invalid audience")

    def _validate_iss(
        self, payload: JWTPayload, issuer: Optional[str]
    ) -> None:
        if issuer is None:
            return

        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        if payload["iss"] != issuer:
            raise InvalidIssuerError("Invalid issuer")


_jwt_global_obj = PyJWT()
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode
