# Generated by Django 5.0 on 2023-12-26 18:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0004_remove_user_seed'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='clientKey',
            field=models.CharField(default=1, max_length=512),
            preserve_default=False,
        ),
    ]
