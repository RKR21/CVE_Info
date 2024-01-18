from celery import shared_task
from .functions import calculate
@shared_task(bind=True)
def compute_stats(self, body, query, data_context):
    total_results = body.get('totalResults')
    data_context = calculate.parse_data(query, total_results, data_context)
    print("Success Returning now")
    return data_context