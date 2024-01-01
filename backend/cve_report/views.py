from django.shortcuts import render
import requests
from rest_framework.response import Response
import json
from .models import CVEReport, Link, Tag
from .serializers import CVESearchSerializer, CVEReportSerializer
from rest_framework.decorators import api_view
from .functions import query

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
    # Get cve instance if it exists in DB
    query_set = CVEReport.objects.filter(name=cve_id)
    if query_set and cve_id in query_set[0].name:
        report_exists = CVEReport.objects.get(name=cve_id)

        serializer = CVEReportSerializer(report_exists)
        print("EXISTS ALREADY")
        return Response(serializer.data)
    else:
        if cve_id:
            # If 'cve_id' is present, create a dictionary to serialize
            data_to_serialize = {'cve_Id': cve_id}
            serializer = CVESearchSerializer(data=data_to_serialize)

            if serializer.is_valid():
                validated_data = serializer.validated_data
                cve_id = validated_data.get("cve_Id")

                nvd_response = query.query_nvd(cve_id)
                report_object = query.generate(nvd_response)
                return Response({'message': f'Received valid data with CVE ID: {cve_id}'})
            else:
                return Response({'error': 'Invalid data received'})
        else:
            return Response({'error': 'No CVE ID provided in the request'})
