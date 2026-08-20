from django.db import migrations, models

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):
    """
    Index token_family, which refresh token reuse protection filters on when it revokes
    a compromised family on the token endpoint (see AbstractRefreshToken.revoke_family).
    Without it, every sweep scans the whole refresh token table.
    """

    dependencies = [
        ("oauth2_provider", "0021_translatable_field_labels"),
        migrations.swappable_dependency(oauth2_settings.REFRESH_TOKEN_MODEL),
    ]

    operations = [
        migrations.AddIndex(
            model_name="refreshtoken",
            index=models.Index(fields=["token_family"], name="oauth2_prov_token_f_996e8a_idx"),
        ),
    ]
