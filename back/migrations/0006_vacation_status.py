# Generated by Django 5.1.7 on 2025-05-07 14:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('back', '0005_remove_vacation_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='vacation',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')], default='pending', max_length=10),
        ),
    ]
