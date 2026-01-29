from django.core.management.base import BaseCommand

from ...models import clear_expired


class Command(BaseCommand):  # pragma: no cover
    help = "Can be run as a cronjob or directly to clean out expired tokens"

    def handle(self, *args, **options):
        clear_expired()
