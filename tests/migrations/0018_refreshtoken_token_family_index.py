from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("tests", "0017_translatable_field_labels"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="custompkrefreshtoken",
            index=models.Index(fields=["token_family"], name="tests_custo_token_f_30673b_idx"),
        ),
        migrations.AddIndex(
            model_name="samplerefreshtoken",
            index=models.Index(fields=["token_family"], name="tests_sampl_token_f_77b84a_idx"),
        ),
    ]
