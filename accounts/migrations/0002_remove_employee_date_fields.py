from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='employee',
            name='joining_date',
        ),
        migrations.RemoveField(
            model_name='employee',
            name='end_of_contract_date',
        ),
    ] 