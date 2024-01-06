import random
import requests
from cve_report.functions.query import query_nvd, craft_cwe_link
from votd.models import VulnerabilityOfTheDay, Link, Tag
from datetime import date, timedelta
#startIndex parameter

def votd_search():
    scores = {}
    starting_index = random.randrange(0, 232000)
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000&startIndex="
    query_url = base_url + str(starting_index)
    data = requests.get(query_url)
    body = data.json()
    #print(body.get('resultsPerPage'))
    total_results = body.get('resultsPerPage')
    # calculate score for all CVEs
    #print(total_results)
    for i in range(total_results):
        # get vulnerability[i]
        vuln = body.get('vulnerabilities', [])[i]
        score = compute_relevance(vuln)
        id = vuln.get('cve', {}).get('id', '')
        scores[id] = score
    # find max score
    new_votd_id = max_score(scores)
    votd = create_votd_object(new_votd_id, scores[new_votd_id])
    #return scores
    return votd


def compute_relevance(vuln):
    score = 0
    link_list = vuln.get('cve', {}).get('references', [])
    for i in range(len(link_list)):
        score += 1
        if 'tags' in link_list[i]:
            tags = link_list[i]['tags']
            if 'Exploit' in tags:
                score += 1
            if 'Patch' in tags:
                score += 1
    
    return score
        
        
def max_score(scores):
    max = 0
    id = ""
    for key in scores:
        if scores[key] > max:
            max = scores[key]
            id = key
    print(f'{id} : {max}')
    return id

def create_votd_object(id, score):
    response = query_nvd(id)
    new_report = VulnerabilityOfTheDay()
    # add relevance score and date posted(next day)
    new_report.relevance_score = score
    new_report.date_posted = date.today() + timedelta(days=1)
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
