"""The OpenID Connect ``claims`` authentication request parameter (Core 1.0
section 5.5)."""

import json
import math

from oauthlib.common import Request as OauthlibRequest
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError


# The top-level members of a claims request this OP understands (section 5.5).
CLAIMS_REQUEST_MEMBERS = ("userinfo", "id_token")

# The members of an individual claim request this OP understands (section 5.5.1).
CLAIM_REQUEST_MEMBERS = ("essential", "value", "values")

CLAIMS_PARAMETER_URI = "https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter"

# How deeply a requested value / values may nest. Claim values are scalars or
# shallow objects (``address``); a bound keeps every walk over them cheap.
MAX_VALUE_DEPTH = 16

# The largest claims request accepted, as normalized JSON. It is copied onto every
# access token, so it is kept small; real requests are a few hundred bytes.
MAX_CLAIMS_REQUEST_SIZE = 16 * 1024

# Integers beyond this lose precision in JSON implementations that use doubles,
# and in some JSON database columns.
MAX_SAFE_INTEGER = 2**53

# Claims every ID Token carries or the OP sets from the authentication itself, so
# requesting them releases no information about the End-User.
PROTOCOL_CLAIMS = ("sub", "acr", "auth_time")


def _invalid(description: str, request: OauthlibRequest | None) -> InvalidRequestError:
    return InvalidRequestError(description=description, uri=CLAIMS_PARAMETER_URI, request=request)


def normalize_claims_request(claims: object, request: OauthlibRequest | None = None) -> dict:
    """
    Validate a parsed ``claims`` request and return it with only the members
    this OP understands.

    ``userinfo`` and ``id_token`` must be JSON objects whose values are ``null``
    or a JSON object (section 5.5.1); ``essential``, when sent, must be a boolean
    and ``values`` an array. Members that are not understood MUST be ignored
    (sections 5.5 and 5.5.1), so any other top-level member, and any member of an
    individual claim request other than ``essential``, ``value`` and ``values``,
    is dropped. A missing or empty value (RFC 6749 section 3.1) is an empty request.

    Raises ``InvalidRequestError`` for a malformed request. Error descriptions
    never repeat the client's claim names, so they stay within the characters
    RFC 6749 section 4.1.2.1 allows.
    """
    if claims is None or claims == "":
        return {}
    if not isinstance(claims, dict):
        raise _invalid("The claims parameter must be a JSON object.", request)

    normalized = {}
    for member in CLAIMS_REQUEST_MEMBERS:
        if member not in claims:
            continue
        requested = claims[member]
        if not isinstance(requested, dict):
            raise _invalid(f"The '{member}' member of the claims parameter must be a JSON object.", request)
        normalized_member = {}
        for name, spec in requested.items():
            if not _is_storable_string(name):
                raise _invalid(f"A claim name in the '{member}' member {_UNSTORABLE_STRING}.", request)
            if spec is None:
                normalized_member[name] = None
                continue
            if not isinstance(spec, dict):
                raise _invalid(
                    f"A claim request in the '{member}' member must be null or a JSON object.", request
                )
            if "essential" in spec and not isinstance(spec["essential"], bool):
                raise _invalid(
                    f"'essential' of a claim request in the '{member}' member must be a boolean.", request
                )
            if "values" in spec and not isinstance(spec["values"], list):
                raise _invalid(
                    f"'values' of a claim request in the '{member}' member must be an array.", request
                )
            for key in ("value", "values"):
                problem = _value_problem(spec[key]) if key in spec else None
                if problem:
                    raise _invalid(f"'{key}' of a claim request in the '{member}' member {problem}.", request)
            normalized_member[name] = {k: v for k, v in spec.items() if k in CLAIM_REQUEST_MEMBERS}
        normalized[member] = normalized_member
    if len(json.dumps(normalized)) > MAX_CLAIMS_REQUEST_SIZE:
        raise _invalid("The claims parameter is too large.", request)
    return normalized


_UNSTORABLE_STRING = "contains a NUL character or invalid Unicode"


def _is_storable_string(value: str) -> bool:
    """Whether a string can be stored and sent on: valid UTF-8 (no lone
    surrogates, which Python's JSON parser accepts) and no NUL, which a
    PostgreSQL ``jsonb`` column cannot hold."""
    if "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _value_problem(value: object) -> str | None:
    """
    Why a requested ``value`` / ``values`` can't be accepted, or ``None``.

    Python's JSON parser also accepts ``NaN``, ``Infinity``, overflowing numbers
    and lone surrogates, which JSON (and so a JSON database column) cannot hold,
    and nesting deep enough to exhaust the recursion limit of anything that later
    walks it. The walk is iterative, so the check itself cannot.
    """
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_VALUE_DEPTH:
            return "is nested too deeply"
        if isinstance(item, float) and not math.isfinite(item):
            return "contains a number JSON cannot represent"
        if isinstance(item, (int, float)) and not isinstance(item, bool) and abs(item) > MAX_SAFE_INTEGER:
            return "contains a number too large to compare exactly"
        if isinstance(item, str) and not _is_storable_string(item):
            return _UNSTORABLE_STRING
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            stack.extend((key, depth + 1) for key in item)
            stack.extend((child, depth + 1) for child in item.values())
    return None


def is_subset_claims_request(subset: dict, original: dict) -> bool:
    """Whether a normalized claims request only drops individual claim requests
    from ``original``, keeping every other one unchanged (partial consent)."""
    for member, requested in subset.items():
        if member not in original:
            return False
        for name, spec in requested.items():
            if name not in original[member] or not _json_equal(spec, original[member][name]):
                return False
    return True


def requests_claim_value(spec: object) -> bool:
    """Whether an individual claim request asks for a particular ``value`` or
    one of ``values`` (section 5.5.1)."""
    return isinstance(spec, dict) and ("value" in spec or isinstance(spec.get("values"), list))


def requested_claim_names(claims: object) -> set[str]:
    """The names of the individual claims a normalized claims request asks for,
    for the ID Token and UserInfo together, other than the protocol claims
    (``sub``, ``acr``, ``auth_time``), which release nothing about the End-User."""
    if not isinstance(claims, dict):
        return set()
    names = set()
    for member in CLAIMS_REQUEST_MEMBERS:
        requested = claims.get(member)
        if isinstance(requested, dict):
            names.update(requested)
    return names - set(PROTOCOL_CLAIMS)


def _json_equal(a: object, b: object) -> bool:
    """Equality of two JSON values, which, unlike Python's, never equates a
    boolean with a number (``true`` is not ``1``), at any depth."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    return a == b


def claim_value_matches(value: object, spec: dict | None) -> bool:
    """
    Whether a claim value satisfies an individual claim request.

    A claim requested with ``value`` or ``values`` is returned only when its
    value equals the requested one, or one of them (section 5.5.1).
    """
    if not isinstance(spec, dict):
        return True
    # Compare the claim as it is sent, so a UUID matches its string and a tuple its array.
    try:
        value = json.loads(json.dumps(value, default=str))
    except (TypeError, ValueError):
        # Not serializable as is (a circular structure, a tuple as a key): compare
        # the value the validator supplied, unchanged.
        pass
    if "value" in spec:
        return _json_equal(value, spec["value"])
    if isinstance(spec.get("values"), list):
        return any(_json_equal(value, requested) for requested in spec["values"])
    return True


def safe_normalize_claims_request(claims: object) -> dict:
    """
    ``normalize_claims_request`` for a claims request that was already accepted,
    or that could not be refused, such as one restored from a grant or token:
    a malformed request is treated as empty rather than raising.
    """
    if not isinstance(claims, dict):
        return {}
    try:
        return normalize_claims_request(claims)
    except InvalidRequestError:
        return {}
