from django.core.management.base import BaseCommand, CommandError
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
        batch_size = options["batch_size"]
        if batch_size < 1:
            raise CommandError("--batch-size must be a positive integer.")
        Application = get_application_model()
        now = timezone.now()
        expired = Application.objects.filter(
            registration_source=Application.RegistrationSource.CIMD,
            cimd_expires_at__lt=now,
        ).order_by("pk")
        deleted = 0
        last_pk = None
        while True:
            # Page with a pk cursor instead of materializing every candidate id:
            # the expired set can be attacker-sized, and the cursor also skips
            # past rows kept alive by live tokens instead of re-scanning them.
            page = expired if last_pk is None else expired.filter(pk__gt=last_pk)
            batch = list(page.values_list("pk", flat=True)[:batch_size])
            if not batch:
                break
            last_pk = batch[-1]
            with transaction.atomic():
                # Lock the batch so the liveness check and the delete are one
                # atomic unit: inserting a token takes a share lock on its
                # application row (the FK check), which conflicts with this
                # exclusive lock. A concurrently minted token is therefore
                # either already visible to the check below or its insert
                # waits until this transaction ends — it can never be silently
                # cascade-deleted in between. Re-checking registration_source
                # and cimd_expires_at under the lock drops candidates whose
                # provenance changed or whose registration was refreshed since
                # the collection query above, so only rows that are still CIMD
                # and still expired are ever deleted.
                locked = set(
                    Application.objects.select_for_update()
                    .filter(
                        pk__in=batch,
                        registration_source=Application.RegistrationSource.CIMD,
                        cimd_expires_at__lt=now,
                    )
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
