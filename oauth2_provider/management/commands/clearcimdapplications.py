from django.core.management.base import BaseCommand
from django.utils import timezone

from ...models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
)


class Command(BaseCommand):
    help = (
        "Delete expired CIMD-registered applications that hold no live tokens or grants. "
        "CIMD rows are re-created automatically on a client's next request, so this only "
        "reclaims storage; run it as a cronjob alongside cleartokens."
    )

    def handle(self, *args, **options):
        Application = get_application_model()
        now = timezone.now()
        candidates = Application.objects.filter(
            registration_source=Application.RegistrationSource.CIMD,
            cimd_expires_at__lt=now,
        )
        # Queried from the token side (forward FK) because the reverse accessor
        # names differ on swapped models.
        live = set()
        for model, live_filter in (
            (get_access_token_model(), {"expires__gt": now}),
            (get_id_token_model(), {"expires__gt": now}),
            (get_grant_model(), {"expires__gt": now}),
            (get_refresh_token_model(), {"revoked__isnull": True}),
        ):
            live.update(
                model.objects.filter(application__in=candidates, **live_filter).values_list(
                    "application_id", flat=True
                )
            )
        prunable = candidates.exclude(pk__in=live)
        count = prunable.count()
        prunable.delete()
        self.stdout.write(f"Deleted {count} expired CIMD application(s)")
