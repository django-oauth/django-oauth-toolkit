from datetime import timedelta

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
        "Delete DCR-registered applications (RFC 7591) that hold no live tokens or grants and are "
        "older than --min-age-days. DCR clients that re-register without deregistering leave behind "
        "'ghost' applications; because a client simply re-registers on its next request, deleting a "
        "tokenless ghost only reclaims storage. Run it as a cronjob alongside cleartokens."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--min-age-days",
            type=int,
            default=7,
            help=(
                "Only delete applications registered at least this many days ago (default: 7). "
                "The grace period avoids racing a client that has just registered but has not yet "
                "completed its first authorization, and so does not hold a token yet. Use 0 to "
                "delete every tokenless DCR application regardless of age."
            ),
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Applications locked and deleted per transaction (default: 1000).",
        )

    def handle(self, *args, **options):
        min_age_days = options["min_age_days"]
        if min_age_days < 0:
            raise CommandError("--min-age-days must be zero or a positive integer.")
        batch_size = options["batch_size"]
        if batch_size < 1:
            raise CommandError("--batch-size must be a positive integer.")
        Application = get_application_model()
        now = timezone.now()
        cutoff = now - timedelta(days=min_age_days)
        candidates = Application.objects.filter(
            registration_source=Application.RegistrationSource.DCR,
            created__lte=cutoff,
        ).order_by("pk")
        deleted = 0
        last_pk = None
        while True:
            # Page with a pk cursor instead of materializing every candidate id:
            # under DCR the application store is client-mintable, so the candidate
            # set can be large, and the cursor also skips past rows kept alive by
            # live tokens instead of re-scanning them.
            page = candidates if last_pk is None else candidates.filter(pk__gt=last_pk)
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
                # and created under the lock drops candidates whose provenance
                # changed since the collection query above, so only rows that
                # are still DCR and still past the age cutoff are ever deleted.
                locked = set(
                    Application.objects.select_for_update()
                    .filter(
                        pk__in=batch,
                        registration_source=Application.RegistrationSource.DCR,
                        created__lte=cutoff,
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
        self.stdout.write(f"Deleted {deleted} orphaned DCR application(s)")
