import random
import requests
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
    print(total_results)
    for i in range(total_results):
        # get vulnerability[i]
        vuln = body.get('vulnerabilities', [])[i]
        score = compute_relevance(vuln)
        id = vuln.get('cve', {}).get('id', '')
        scores[id] = score
    # find max score
    new_votd_id = max_score(scores)
    #return scores
    return new_votd_id


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
