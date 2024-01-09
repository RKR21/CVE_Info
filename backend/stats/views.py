from django.shortcuts import render
import requests

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
    query_link = baseUrl + exact_match_string
    response = requests.get(query_link)
    if response.status_code == 200:
        # Get the JSON object from the response
        response_json = response.json()
        #print(response_json)
        return response
    
    else:
        error_message = "Error: Failed to retrieve data from NVD API. Status code: {response.status_code}"
        print(error_message)
    
    return render(request, 'search_results.html', {'query' : query})