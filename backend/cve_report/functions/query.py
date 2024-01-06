import requests
from rest_framework.response import Response
from ..models import CVEReport, Link, Tag


""" automated system:
use celery to schedule this. 
go through a block of 2000 CVEs and calculate a relevence score.
Relevance score criteria:
* one point for each nvd_link
* github links count for two points
* exploit links count for two points
* keep track in a dictionary, whichever CVE has highest score
gets displayed the next day
store the vulnerabilities of the day in the database so you dont repeat 

Feature idea: Let users search CWE-Ids and we return list of CVEs with that ID
that have had high relevance scores(vuln of day)
"""
def query_nvd(cve):
    nvd_link = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
    query_link = nvd_link + cve
    test_link = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218"
    params = {"cve_id" : cve}
    response = requests.get(query_link)
    if response.status_code == 200:
        # Get the JSON object from the response
        response_json = response.json()
        #print(response_json)
        return response
        

    else:
        error_message = "Error: Failed to retrieve data from NVD API. Status code: {response.status_code}"
        print(error_message)
    return Response({'error': error_message}, status=response.status_code)
def generate(response):     # make CVEReport object
    new_report = CVEReport()
    body = response.json()
    # get name
    new_report.name = body.get('vulnerabilities', [])[0].get('cve', {}).get('id', '')
    # get description
    new_report.description = body.get('vulnerabilities', [])[0].get('cve', {}).get('descriptions', [])[0].get('value')
    # get cvss3 score
    vulnerability = body.get('vulnerabilities', [])[0]
    cvss_three_exists = vulnerability.get('cve', {}).get('metrics', {}).get('cvssMetricV30')
    if cvss_three_exists:
        new_report.cvss_three = cvss_three_exists[0].get('cvssData', {}).get(
            'baseScore')
        new_report.cvss_three_vector = cvss_three_exists[0].get('cvssData', {}).get(
            'vectorString')
    # get cvss2 vector
    cvss_two_exists = vulnerability.get('cve', {}).get('metrics', {}).get('cvssMetricV2')
    if cvss_two_exists:
        new_report.cvss_two = cvss_two_exists[0].get('cvssData', {}).get(
            'baseScore')
        new_report.cvss_two_vector = cvss_two_exists[0].get('cvssData', {}).get(
            'vectorString')
        
    new_report.cwe_id = body.get('vulnerabilities', [])[0].get('cve', {}).get(
        'weaknesses', [])[0].get('description', [])[0].get('value', None)
    # get cwe link
    new_report.cwe_link = craft_cwe_link(new_report.cwe_id)
    # get nvd links
    link_list = body.get('vulnerabilities', [])[0].get('cve', {}).get('references', [])
    #print(link_tag_string)
    new_report.save()
    for i in range(len(link_list)):
        new_link = Link()
        new_link.url = link_list[i]["url"]
        if 'tags' in link_list[i]:
            tags = link_list[i]['tags']
            new_link.save()
            new_link.tags.clear()
            for tag in tags:
                tag, created = Tag.objects.get_or_create(name=tag)
                new_link.tags.add(tag)
        new_link.save()
        new_report.nvd_links.add(new_link)
    new_report.save()


def craft_cwe_link(cwe_id):
    id = cwe_id.split("-")
    base_url = "https://cwe.mitre.org/data/definitions/"
    return base_url + id[1] + ".html"

