import django.db.models.deletion
from django.db import migrations, models

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):
    dependencies = [
        (
            "tests",
            "0021_basetestapplication_require_pushed_authorization_requests_and_more",
        ),
        migrations.swappable_dependency(oauth2_settings.AUTHORIZATION_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="custompkaccesstoken",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
                verbose_name="authorization",
            ),
        ),
        migrations.AddField(
            model_name="custompkrefreshtoken",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
                verbose_name="authorization",
            ),
        ),
        migrations.AddField(
            model_name="localidtoken",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
                verbose_name="authorization",
            ),
        ),
        migrations.AddField(
            model_name="sampleaccesstoken",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
                verbose_name="authorization",
            ),
        ),
        migrations.AddField(
            model_name="sampledevicegrant",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
                verbose_name="authorization",
            ),
        ),
        migrations.AddField(
            model_name="samplegrant",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
                verbose_name="authorization",
            ),
        ),
        migrations.AddField(
            model_name="samplegrant",
            name="exchanged_at",
            field=models.DateTimeField(blank=True, null=True, verbose_name="exchanged at"),
        ),
        migrations.AddField(
            model_name="samplerefreshtoken",
            name="authorization",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="%(app_label)s_%(class)s",
                to=oauth2_settings.AUTHORIZATION_MODEL,
                verbose_name="authorization",
            ),
        ),
    ]
