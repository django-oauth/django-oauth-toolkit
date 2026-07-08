# flake8: noqa
from .authentication import OAuth2Authentication, OAuth2ProtectedResourceAuthentication
from .permissions import (
    IsAuthenticatedOrTokenHasScope,
    TokenHasReadWriteScope,
    TokenHasResourceScope,
    TokenHasScope,
    TokenMatchesOASRequirements,
)
