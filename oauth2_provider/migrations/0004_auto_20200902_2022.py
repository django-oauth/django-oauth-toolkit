import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('oauth2_provider', '0003_auto_20201211_1314'),
    ]

    operations = [
        migrations.AddField(
            model_name='application',
            name='algorithm',
            field=models.CharField(blank=True, choices=[("", "No OIDC support"), ('RS256', 'RSA with SHA-2 256'), ('HS256', 'HMAC with SHA-2 256')], default='', max_length=5),
        ),
        migrations.AlterField(
            model_name='application',
            name='authorization_grant_type',
            field=models.CharField(choices=[('authorization-code', 'Authorization code'), ('implicit', 'Implicit'), ('password', 'Resource owner password-based'), ('client-credentials', 'Client credentials'), ('openid-hybrid', 'OpenID connect hybrid')], max_length=32),
        ),
        migrations.CreateModel(
            name='IDToken',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ("jti", models.UUIDField(unique=True, default=uuid.uuid4, editable=False, verbose_name="JWT Token ID")),
                ('expires', models.DateTimeField()),
                ('scope', models.TextField(blank=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('application', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=oauth2_settings.APPLICATION_MODEL)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='oauth2_provider_idtoken', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
                'swappable': 'OAUTH2_PROVIDER_ID_TOKEN_MODEL',
            },
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='id_token',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='access_token', to=oauth2_settings.ID_TOKEN_MODEL),
        ),
        migrations.AddField(
            model_name="grant",
            name="nonce",
            field=models.CharField(blank=True, max_length=255, default=""),
        ),
        migrations.AddField(
            model_name="grant",
            name="claims",
            field=models.TextField(blank=True),
        ),
    ]
