from rest_framework import serializers

class CVESearchSerializer(serializers.Serializer):
    cve_Id = serializers.CharField()

