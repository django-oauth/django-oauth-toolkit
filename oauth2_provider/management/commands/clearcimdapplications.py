from django.core.management.base import BaseCommand
from django.db import transaction
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

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Applications locked and deleted per transaction (default: 1000).",
        )

    def handle(self, *args, **options):
        Application = get_application_model()
        batch_size = options["batch_size"]
        now = timezone.now()
        candidate_ids = list(
            Application.objects.filter(
                registration_source=Application.RegistrationSource.CIMD,
                cimd_expires_at__lt=now,
            ).values_list("pk", flat=True)
        )
        deleted = 0
        for start in range(0, len(candidate_ids), batch_size):
            batch = candidate_ids[start : start + batch_size]
            with transaction.atomic():
                # Lock the batch so the liveness check and the delete are one
                # atomic unit: inserting a token takes a share lock on its
                # application row (the FK check), which conflicts with this
                # exclusive lock. A concurrently minted token is therefore
                # either already visible to the check below or its insert
                # waits until this transaction ends — it can never be silently
                # cascade-deleted in between. Re-checking cimd_expires_at
                # drops candidates whose registration was refreshed since the
                # collection query above.
                locked = set(
                    Application.objects.select_for_update()
                    .filter(pk__in=batch, cimd_expires_at__lt=now)
                    .values_list("pk", flat=True)
                )
                # Queried from the token side (forward FK) because the reverse
                # accessor names differ on swapped models.
                live = set()
                for model, live_filter in (
                    (get_access_token_model(), {"expires__gt": now}),
                    (get_id_token_model(), {"expires__gt": now}),
                    (get_grant_model(), {"expires__gt": now}),
                    (get_refresh_token_model(), {"revoked__isnull": True}),
                ):
                    live.update(
                        model.objects.filter(application_id__in=locked, **live_filter).values_list(
                            "application_id", flat=True
                        )
                    )
                prunable = locked - live
                Application.objects.filter(pk__in=prunable).delete()
                deleted += len(prunable)
        self.stdout.write(f"Deleted {deleted} expired CIMD application(s)")
