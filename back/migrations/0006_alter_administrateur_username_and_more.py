# Generated by Django 5.1.5 on 2025-03-11 12:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('back', '0005_employes_contrats_employes_magasin_employes_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='administrateur',
            name='username',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='employes',
            name='username',
            field=models.CharField(max_length=50),
        ),
    ]
