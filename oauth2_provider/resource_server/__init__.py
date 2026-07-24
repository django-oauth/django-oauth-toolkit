"""Resource Server role: validating bearer tokens (RFC 7662 introspection,
RFC 8707 audience) and advertising RFC 9728 protected-resource metadata."""

from .www_authenticate import build_bearer_challenge, challenge_status


__all__ = [
    "build_bearer_challenge",
    "challenge_status",
]

