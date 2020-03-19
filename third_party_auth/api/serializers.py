""" Django REST Framework Serializers """

from django.contrib.sites.models import Site
from rest_framework import serializers
from third_party_auth.models import OAuth2ProviderConfig


class UserMappingSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """ Serializer for User Mapping"""
    provider = None
    username = serializers.SerializerMethodField()
    remote_id = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        self.provider = kwargs['context'].get('provider', None)
        super(UserMappingSerializer, self).__init__(*args, **kwargs)

    def get_username(self, social_user):
        """ Gets the edx username from a social user """
        return social_user.user.username

    def get_remote_id(self, social_user):
        """ Gets remote id from social user based on provider """
        return self.provider.get_remote_id_from_social_auth(social_user)


class SiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Site
        exclude = []


class OAuthProviderSerializer(serializers.ModelSerializer):
    site = SiteSerializer()

    class Meta:
        model = OAuth2ProviderConfig
        fields = '__all__'