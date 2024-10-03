import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'controller.settings')

app = Celery('controller')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.broker_connection_retry_on_startup = True

app.autodiscover_tasks()


