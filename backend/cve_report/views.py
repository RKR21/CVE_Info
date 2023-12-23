from django.shortcuts import render
import requests
from rest_framework.response import Response
import json
from .models import CVEReport
from .serializers import CVESearchSerializer
from rest_framework.decorators import api_view


""" def generate_report(request):
    serializer = CVESearchSerializer(data=request.data)
    if serializer.is_valid():
        validated_data = serializer.validated_data
        cve_id = validated_data.get("cve_id")

        nvd_response = query_nvd(cve_id)


        return Response({'message': f'Received valid data with CVE ID: {cve_id}'})
    else:
        return Response({'error': 'Invalid data received'}) """
@api_view(['POST'])
def generate_report(request):
    # Get the 'cve_id' from the request.GET dictionary
    cve_id = request.data.get('cve_Id')

    if cve_id:
        # If 'cve_id' is present, create a dictionary to serialize
        data_to_serialize = {'cve_Id': cve_id}
        serializer = CVESearchSerializer(data=data_to_serialize)

        if serializer.is_valid():
            validated_data = serializer.validated_data
            cve_id = validated_data.get("cve_Id")

            nvd_response = query_nvd(cve_id)
            report_object = generate(nvd_response)
            return Response({'message': f'Received valid data with CVE ID: {cve_id}'})
        else:
            return Response({'error': 'Invalid data received'})
    else:
        return Response({'error': 'No CVE ID provided in the request'})


    
def query_nvd(cve):
    nvd_link = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
    query_link = nvd_link + cve
    test_link = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218"
    params = {"cve_id" : cve}
    response = requests.get(query_link)
    if response.status_code == 200:
        # Get the JSON object from the response
        return response
        response_json = response.json()
        print(response_json)

    else:
        error_message = "Error: Failed to retrieve data from NVD API. Status code: {response.status_code}"
        print(error_message)
    return Response({'error': error_message}, status=response.status_code)

def generate(response):     # make CVEReport object
    new_report = CVEReport()
    body = response.json()
    new_report.name = body.get('vulnerabilities', [])[0].get('cve', {}).get('id', '')
    print(new_report.name)

    #print(body)