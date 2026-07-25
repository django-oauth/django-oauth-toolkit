from django.core.management.base import BaseCommand

from ...models import clear_expired, refresh_token_expire_timedelta


class Command(BaseCommand):
    help = "Can be run as a cronjob or directly to clean out expired tokens"

    def handle(self, *args, **options):
        if refresh_token_expire_timedelta() is None:
            self.stderr.write(
                self.style.WARNING(
                    "REFRESH_TOKEN_EXPIRE_SECONDS is not set (or is 0), so refresh tokens never "
                    "age-expire. cleartokens will only remove revoked and orphaned refresh tokens; "
                    "expired access and ID tokens that are still bound to a refresh token are kept "
                    "as long as that refresh token lives. Set REFRESH_TOKEN_EXPIRE_SECONDS to enable "
                    "expiry-based cleanup."
                )
            )
        clear_expired()
