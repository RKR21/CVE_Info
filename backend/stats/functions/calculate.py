import math
import requests

from .generate_graphs import generate_cvss_graphs, generate_num_cves_per_year_graph, generate_avg_yearly_base_score_graph

#from ..models import QueryStats


""" Celery beat task to go through all search terms and their Stats
and update them if they havent been updated in the last month """


""" Stats to get:
* Average base score cvss 2 and/or three
* tallies of AC, AV, Au, C, I, A
* tallies of AV, AC, PR, UI, S, C, I, A
* populate dictionary = {year : [num CVEs in year]}
* populate dictionary = {year : [all base scores for year]} - > then calculate at the end
* tallies of CWE's for bar chart
"""

# Queries nvd with search term and calls helper functions to calculate stats
def parse_data(query, total_results, data_context):
    iterations = math.ceil(total_results / 2000)
    #print(f"ITERATIONS : {total_results}{iterations}")
    avg_V2_base_score = 0
    avg_V3_base_score = 0
    avg_V3_1_base_score = 0
    V2_occurrences = 0
    V3_occurrences = 0
    V3_1_occurrences = 0
    num_cves_per_year = {}
    yearly_avg_base_score_two = {}
    yearly_avg_base_score_three = {}
    yearly_avg_base_score_three_one = {}
    cvss_two_dict = {
        'AV' : {'L' : 0, 'A' : 0, 'N' : 0},
        'AC' : {'H' : 0, 'M' : 0, 'L' : 0},
        'Au' : {'M' : 0, 'S' : 0, 'N' : 0},
        'C' : {'N' : 0, 'P' : 0, 'C' : 0},
        'I' : {'N' : 0, 'P' : 0, 'C' : 0},
        'A' : {'N' : 0, 'P' : 0, 'C' : 0},
    }
    cvss_three_dict = {
        'AV' : {'N' : 0, 'A' : 0, 'L' : 0, 'P' : 0},
        'AC' : {'H' : 0, 'L' : 0},
        'PR' : {'N' : 0, 'L' : 0, 'H' : 0},
        'UI' : {'N' : 0, 'R' : 0},
        'S' : {'U' : 0, 'C' : 0},
        'C' : {'N' : 0, 'L' : 0, 'H': 0},
        'I' : {'N' : 0, 'L' : 0, 'H': 0},
        'A' : {'N' : 0, 'L' : 0, 'H': 0},
    }
    cvss_three_one_dict = {
        'AV' : {'N' : 0, 'A' : 0, 'L' : 0, 'P' : 0},
        'AC' : {'H' : 0, 'L' : 0},
        'PR' : {'N' : 0, 'L' : 0, 'H' : 0},
        'UI' : {'N' : 0, 'R' : 0},
        'S' : {'U' : 0, 'C' : 0},
        'C' : {'N' : 0, 'L' : 0, 'H': 0},
        'I' : {'N' : 0, 'L' : 0, 'H': 0},
        'A' : {'N' : 0, 'L' : 0, 'H': 0},
    }
    cvss_two_tally = [0] * 6
    cvss_three_tally = [0] * 8
    start_index = 0
    for i in range(iterations):
        
        baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
        exact_match_string = "&keywordExactMatch"
        start_index_string = "&startIndex=" + str(start_index)
        query_link = baseUrl + query + exact_match_string + start_index_string
        response = requests.get(query_link)
        #print(query_link)
        body = response.json()
        """ print(body.get('totalResults'))
        print(body.get('resultsPerPage'))
        print(body.get('vulnerabilities', [])[0].get('cve', {}).get('id')) """
        start_index += 2000
        for j in range(body.get('resultsPerPage')):
            vuln = body.get('vulnerabilities', [])[j]
            if(cvss_two_exists(vuln)):
                V2_occurrences += 1
                avg_V2_base_score += get_cvss_two_metrics(vuln, cvss_two_dict, yearly_avg_base_score_two)
                #avg_V2_base_score = avg_V2_base_score / V2_occurrences
                
            if(cvss_three_exists(vuln)):
                V3_occurrences += 1
                avg_V3_base_score += get_cvss_three_metrics(vuln, cvss_three_dict, yearly_avg_base_score_three)
                #avg_V3_base_score = avg_V3_base_score / V3_occurrences
            if(cvss_three_one_exists(vuln)):
                V3_1_occurrences += 1
                avg_V3_1_base_score += get_cvss_three_metrics(vuln, cvss_three_one_dict, yearly_avg_base_score_three_one)
                #avg_V3_1_base_score = avg_V3_1_base_score / V3_1_occurrences
            # get year of cve
            year = vuln.get('cve', {}).get('published').split('-')[0]
            if year in num_cves_per_year:
                num_cves_per_year[year] += 1
            else:
                num_cves_per_year[year] = 1
    # compute average base scores
    
    if V2_occurrences != 0: avg_V2_base_score = round(avg_V2_base_score / V2_occurrences, 1)
    if V3_occurrences != 0: avg_V3_base_score = round(avg_V3_base_score / V3_occurrences, 1)
    if V3_1_occurrences != 0: avg_V3_1_base_score = round(avg_V3_1_base_score / V3_1_occurrences, 1)
    """ print(num_cves_per_year)
    print(yearly_avg_base_score_two)
    print(yearly_avg_base_score_three)
    print(yearly_avg_base_score_three_one)

    # get yearly averages
    average_dict_arrays(yearly_avg_base_score_two)
    average_dict_arrays(yearly_avg_base_score_three)
    average_dict_arrays(yearly_avg_base_score_three_one)

    print(f"avg yearly V2: {yearly_avg_base_score_two}")
    print(f"avg yearly V3: {yearly_avg_base_score_three}")
    print(f"avg yearly V31: {yearly_avg_base_score_three_one}")
    #print(f"{avg_V2_base_score} and {V2_occurrences}")
    
    print(f"AVG: {avg_V2_base_score}")
    
    print(f"AVG: {avg_V3_base_score}")
    print(f"AVG: {avg_V3_1_base_score}")
    print(f"dict2: {cvss_two_dict}")
    print(f"dict3: {cvss_three_dict}")
    print(f"dict31: {cvss_three_one_dict}") """

    """ # save into search term stats model
    term = QueryStats()
    term.query_name = query
    term.avg_cvss_two = avg_V2_base_score
    term.avg_cvss_three = avg_V3_base_score
    term.avg_cvss_three_one = avg_V3_1_base_score

    term.cvss_two_vector_tallies = cvss_two_dict
    term.cvss_two_vector_tallies = cvss_three_dict
    term.cvss_two_vector_tallies = cvss_three_one_dict

    term.num_cves_per_year = num_cves_per_year
    term.avg_yearly_base_score_V2 = yearly_avg_base_score_two
    term.avg_yearly_base_score_V3 = yearly_avg_base_score_three
    term.avg_yearly_base_score_V3_1 = yearly_avg_base_score_three_one
    term.save() """

    # make graphs
    # cvss_2 pie charts of vector metrics
    # cvss_3 pie charts of vector metrics
    # cvss_3.1 pie charts of vector metrics

    cvss_two_graphs = generate_cvss_graphs(cvss_two_dict, V2_occurrences)
    cvss_three_graphs = generate_cvss_graphs(cvss_three_dict, V3_occurrences)
    cvss_three_one_graphs = generate_cvss_graphs(cvss_three_one_dict, V3_1_occurrences)

    cve_per_year_graph = generate_num_cves_per_year_graph(num_cves_per_year)
    # average the yearly base scores and graph them
    average_dict_arrays(yearly_avg_base_score_two)
    average_dict_arrays(yearly_avg_base_score_three)
    average_dict_arrays(yearly_avg_base_score_three_one)
    avg_V2_base_score_graph = generate_avg_yearly_base_score_graph(yearly_avg_base_score_two)
    avg_V3_base_score_graph = generate_avg_yearly_base_score_graph(yearly_avg_base_score_three)
    avg_V3_1_base_score_graph = generate_avg_yearly_base_score_graph(yearly_avg_base_score_three_one)
    #print(query)
    data_context = {
        "query" : query,
        "total_results" : total_results,
        "V2_occurrences" : V2_occurrences,
        "V3_occurrences" : V3_occurrences,
        "V3_1_occurrences" : V3_1_occurrences,
        "avg_V2_base_score" : avg_V2_base_score,
        "avg_V3_base_score" : avg_V3_base_score,
        "avg_V3_1_base_score" : avg_V3_1_base_score,
        "V2_graphs" : cvss_two_graphs,
        "V3_graphs" : cvss_three_graphs,
        "V3_1_graphs" : cvss_three_one_graphs,
        "cve_per_year_graph" : cve_per_year_graph,
        "avg_V2_base_score_graph" : avg_V2_base_score_graph,
        "avg_V3_base_score_graph" : avg_V3_base_score_graph,
        "avg_V3_1_base_score_graph" : avg_V3_1_base_score_graph,
    }
    #print(data_context)
    return data_context
            #print(j)
    #print(cvss_two_dict)
    

# calls aggregate function to count vector metrics and base score for cvss 2
# also populates yearly average base score dictionary
# returns base score to be added in parse_data function
def get_cvss_two_metrics(vuln, cvss_two_dict, yearly_avg_base_score):
    base_score = 0
    cvss_two = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV2')
    #print(cvss_two)
        #print(cvss_two[0].get('cvssData', {}).get('baseScore'))
    base_score = cvss_two[0].get('cvssData', {}).get('baseScore')
    year = int(vuln.get('cve', {}).get('published').split('-')[0])
    # populate average yearly base score dictionary
    if year not in yearly_avg_base_score:
        yearly_avg_base_score[year] = [1, base_score]
    else:
        yearly_avg_base_score[year][0] += 1
        yearly_avg_base_score[year][1] += base_score

    #print(base_score)
    vector = cvss_two[0].get('cvssData', {}).get('vectorString').split('/')
    aggregate_cvss_dict(cvss_two_dict, vector)
        
        #print(vector)
    return base_score
# calls aggregate function to count vector metrics and base scores for cvss 3
# also populates yearly base score dictionary
# returns base score to be added in parse_data function
def get_cvss_three_metrics(vuln, cvss_three_dict, yearly_avg_base_score):
    base_score = 0
    cvss_three = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV30')
    if cvss_three == None:
        cvss_three = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV31')
    base_score = cvss_three[0].get('cvssData', {}).get('baseScore')
    # populate average yearly base score dictionary
    year = int(vuln.get('cve', {}).get('published').split('-')[0])
    if year not in yearly_avg_base_score:
        yearly_avg_base_score[year] = [1, base_score]
    else:
        yearly_avg_base_score[year][0] += 1
        yearly_avg_base_score[year][1] += base_score
    vector = cvss_three[0].get('cvssData', {}).get('vectorString').split('/')
    vector.pop(0)
    aggregate_cvss_dict(cvss_three_dict, vector)
    return base_score

# populate cvss dictionaries
def aggregate_cvss_dict(dict, vector):
    vector_counter = 0
    #print(vector)
    for key in dict:
        metric = vector[vector_counter].split(':')
        dict[key][metric[1]] += 1
        vector_counter += 1
    #print(dict)
    """ if 'cvssMetricV2' not in metrics:
        print("don't exist V2")
        return False """

def cvss_two_exists(vuln):
    cvss_two = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV2')
    #print(cvss_two)
    if not cvss_two:
        #print("V2 doesnt exist")
        return False
    else:
        return True
def cvss_three_exists(vuln):
    cvss_three = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV30')
    #print(cvss_two)
    if not cvss_three:
        #print("V2 doesnt exist")
        return False
    else:
        return True
def cvss_three_one_exists(vuln):
    cvss_three = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV31')
    #print(cvss_two)
    if not cvss_three:
        #print("V2 doesnt exist")
        return False
    else:
        return True
# averages arrays in dict
def average_dict_arrays(dict):
    for key in dict:
        avg = 0
        avg = dict[key][1] / dict[key][0]
        dict[key].clear()
        dict[key].append(avg)