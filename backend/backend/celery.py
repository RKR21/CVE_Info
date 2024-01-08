from __future__ import absolute_import, unicode_literals
import os

from celery import Celery
from django.conf import settings
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
redis_url = 'redis://127.0.0.1:6379'
app = Celery('get_votd', broker_pool_limit=1, broker=redis_url,
             result_backend='django-db')
app.conf.enable_utc = False

app.conf.update(timezone = 'America/New_York')

app.config_from_object(settings, namespace='CELERY')

# Celery Beat Settings
app.conf.beat_schedule = {
    'find-votd': {
        'task': 'votd.tasks.find_votd',
        'schedule': crontab(hour=14, minute=2),
    }
}
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')