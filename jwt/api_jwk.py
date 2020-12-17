import json
from typing import Dict, List, Optional

from .algorithms import get_default_algorithms
from .exceptions import PyJWKError, PyJWKSetError
from .types import JWKData


class PyJWK:
    def __init__(self, jwk_data: JWKData, algorithm: Optional[str] = None):
        self._algorithms = get_default_algorithms()
        self._jwk_data = jwk_data

        if not algorithm and isinstance(self._jwk_data, dict):
            alg = self._jwk_data.get("alg", None)
            assert isinstance(alg, str)
            algorithm = alg

        if not algorithm:
            raise PyJWKError(
                "Unable to find a algorithm for key: %s" % self._jwk_data
            )

        self.Algorithm = self._algorithms.get(algorithm)

        if not self.Algorithm:
            raise PyJWKError(
                "Unable to find a algorithm for key: %s" % self._jwk_data
            )

        self.key = self.Algorithm.from_jwk(self._jwk_data)

    @staticmethod
    def from_dict(obj: JWKData, algorithm: Optional[str] = None) -> "PyJWK":
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data: str, algorithm: Optional[str] = None) -> "PyJWK":
        obj = json.loads(data)
        return PyJWK.from_dict(obj, algorithm)

    @property
    def key_type(self) -> str:
        kty = self._jwk_data.get("kty", None)
        assert isinstance(kty, str)
        return kty

    @property
    def key_id(self) -> str:
        kid = self._jwk_data.get("kid", None)
        assert isinstance(kid, str)
        return kid

    @property
    def public_key_use(self) -> str:
        use = self._jwk_data.get("use", None)
        assert isinstance(use, str)
        return use


class PyJWKSet:
    def __init__(self, keys: List[JWKData]):
        self.keys = []

        if not keys or not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")

        if len(keys) == 0:
            raise PyJWKSetError("The JWK Set did not contain any keys")

        for key in keys:
            self.keys.append(PyJWK(key))

    @staticmethod
    def from_dict(obj: Dict[str, List[JWKData]]) -> "PyJWKSet":
        keys = obj.get("keys", [])
        return PyJWKSet(keys)

    @staticmethod
    def from_json(data: str) -> "PyJWKSet":
        obj = json.loads(data)
        return PyJWKSet.from_dict(obj)
