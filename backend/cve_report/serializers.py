from rest_framework import serializers
from .models import CVEReport, Link, Tag


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ['name']

class LinkSerializer(serializers.ModelSerializer):
    tags = TagSerializer(many=True, read_only=True)

    class Meta:
        model = Link
        fields = ['url', 'tags']
class CVESearchSerializer(serializers.Serializer):
    cve_Id = serializers.CharField()

class CVEReportSerializer(serializers.ModelSerializer):
    nvd_links = LinkSerializer(many=True, read_only=True)
    class Meta:
        model = CVEReport
        fields = '__all__'