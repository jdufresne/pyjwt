import datetime
from typing import Dict, List, Union

JOSEHeader = Dict[str, str]

JWTPayloadScalar = Union[bool, int, str, datetime.datetime]
JWTPayload = Dict[str, Union[JWTPayloadScalar, List[JWTPayloadScalar]]]

JWKData = Dict[str, Union[str, List[str]]]

DecodeOptions = Dict[str, Union[bool, List[str]]]
