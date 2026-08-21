from django.dispatch import Signal


app_authorized = Signal()  # providing_args=["request", "token"]
