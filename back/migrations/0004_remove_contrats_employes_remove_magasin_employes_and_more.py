# Generated by Django 5.1.5 on 2025-02-13 14:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('back', '0003_rename_name_administrateur_username'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='contrats',
            name='employes',
        ),
        migrations.RemoveField(
            model_name='magasin',
            name='employes',
        ),
        migrations.RemoveField(
            model_name='planning',
            name='employes',
        ),
        migrations.AlterField(
            model_name='administrateur',
            name='username',
            field=models.CharField(max_length=50, unique=True),
        ),
        migrations.DeleteModel(
            name='Employes',
        ),
    ]
