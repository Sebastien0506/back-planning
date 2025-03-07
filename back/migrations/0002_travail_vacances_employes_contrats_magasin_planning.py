# Generated by Django 5.1.5 on 2025-02-13 13:56

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('back', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Travail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_job', models.TimeField()),
                ('end_job', models.TimeField()),
            ],
        ),
        migrations.CreateModel(
            name='Vacances',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_date', models.DateTimeField()),
                ('end_date', models.DateTimeField()),
            ],
        ),
        migrations.CreateModel(
            name='Employes',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('lastname', models.CharField(max_length=50)),
                ('email', models.EmailField(max_length=50, unique=True)),
                ('password', models.CharField(max_length=128)),
                ('administrateurs', models.ManyToManyField(to='back.administrateur')),
            ],
        ),
        migrations.CreateModel(
            name='Contrats',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type_de_contrat', models.CharField(max_length=50)),
                ('employes', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='back.employes')),
            ],
        ),
        migrations.CreateModel(
            name='Magasin',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('administrateurs', models.ManyToManyField(to='back.administrateur')),
                ('employes', models.ManyToManyField(to='back.employes')),
            ],
        ),
        migrations.CreateModel(
            name='Planning',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_planning', models.DateField()),
                ('end_planning', models.DateField()),
                ('employes', models.ManyToManyField(to='back.employes')),
            ],
        ),
    ]
