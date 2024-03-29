# Generated by Django 4.2.9 on 2024-01-08 15:07

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Link',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField()),
            ],
        ),
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='VulnerabilityOfTheDay',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=20)),
                ('description', models.TextField()),
                ('cvss_two_vector', models.CharField(max_length=50)),
                ('cvss_three_vector', models.CharField(max_length=50)),
                ('cvss_two', models.FloatField(blank=True, null=True)),
                ('cvss_three', models.FloatField(blank=True, null=True)),
                ('cwe_id', models.CharField(max_length=10)),
                ('cwe_name', models.CharField(max_length=200)),
                ('cwe_link', models.URLField()),
                ('date_posted', models.DateField()),
                ('relevance_score', models.IntegerField()),
                ('nvd_links', models.ManyToManyField(related_name='nvd_links', to='votd.link')),
            ],
        ),
        migrations.AddField(
            model_name='link',
            name='tags',
            field=models.ManyToManyField(to='votd.tag'),
        ),
    ]
