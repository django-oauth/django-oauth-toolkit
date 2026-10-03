from django.db import migrations, models


class Migration(migrations.Migration):
    """Rename PushedAuthorizationRequest to StoredAuthorizationRequest.

    The store holds validated authorization requests from more than the RFC 9126
    endpoint, so it is no longer named after PAR. Rows survive: the table is renamed
    in place, so outstanding request_uri values stay redeemable.

    The swappable setting is renamed first, so the operations after it skip the
    database work when the project swaps the model under the new setting
    (OAUTH2_PROVIDER_STORED_AUTHORIZATION_REQUEST_MODEL), as the live model does.
    The unique constraint's name derives from the class name, so it is re-created
    under the new name.
    """

    dependencies = [
        ("oauth2_provider", "0028_application_client_display_metadata"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="pushedauthorizationrequest",
            options={"swappable": "OAUTH2_PROVIDER_STORED_AUTHORIZATION_REQUEST_MODEL"},
        ),
        migrations.RenameModel(
            old_name="PushedAuthorizationRequest",
            new_name="StoredAuthorizationRequest",
        ),
        migrations.RemoveConstraint(
            model_name="storedauthorizationrequest",
            name="oauth2_provider_pushedauthorizationrequest_unique_request_uri",
        ),
        migrations.AddConstraint(
            model_name="storedauthorizationrequest",
            constraint=models.UniqueConstraint(
                fields=("request_uri",),
                name="oauth2_provider_storedauthorizationrequest_unique_request_uri",
            ),
        ),
    ]
