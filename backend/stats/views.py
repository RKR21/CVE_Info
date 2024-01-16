from django.shortcuts import render
import requests
from .functions.calculate import parse_data
from .tasks import compute_stats
import requests
from celery.result import AsyncResult


# Create your views here.

def search_view(request):
    #search_query = request.get('q', '')

    return render(request, 'search_page.html')
""" Stats to get:
* Average base score cvss 2 and/or three
* tallies of AC, AV, Au, C, I, A
* tallies of AV, AC, PR, UI, S, C, I, A
* populate dictionary = {year : [cve ID's]}
* populate dictionary = {year : average base score}
* tallies of CWE's for bar chart
"""

def get_stats(request):
    query = request.GET.get('query', '')
    baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
    exact_match_string = "&keywordExactMatch"
    query_link = baseUrl + query + exact_match_string
    response = requests.get(query_link)
    if response.status_code == 200:
        # Get the JSON object from the response
        body = response.json()
        data_context = {}
        task_result = compute_stats.delay(body, query, data_context)
        data_context = task_result.get()
        
    
    else:
        error_message = "Error: Failed to retrieve data from NVD API. Status code: {response.status_code}"
        print(error_message)
    #print(data_context)
    # if no results found, display blank page
    if body.get("totalResults") == 0:
        return render(request, 'no_results.html', {"query" : query})
    return render(request, 'search_results.html', {'stats' : data_context})
# find most interesting vulnerabilities and display them
# display top 5 most common CWEs