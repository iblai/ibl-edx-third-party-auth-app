""" Django REST Framework Serializers """

import json

from django.contrib.sites.models import Site
from rest_framework import serializers
from third_party_auth.models import OAuth2ProviderConfig


class JsonSettingField(serializers.Field):
    """Returns a value from a json field"""
    def __init__(self, *args, **kwargs):
        self.model_field = kwargs.pop('model_field')
        self.key = kwargs.pop('key')
        super(JsonSettingField, self).__init__(*args, **kwargs)

    def to_representation(self, value):
        """Load self.key from model_field

        TODO: different behavior of value is model instance vs field value
          - if model instance (source=*), getattr(self.model_field)
          - if not model instance, try to load value directly

        This is currently very specific to my use case but could be made more
        generic.
        """
        try:
            d = json.loads(getattr(value, self.model_field))
        except ValueError:
            return ''
        return d[self.key]

    def to_internal_value(self, data):
        """Add the field name to the data dict"""
        return {self.field_name: data}


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


class OAuthProviderSerializer(serializers.ModelSerializer):
    backend = 'keycloak'

    auth_url = JsonSettingField(key='AUTHORIZATION_URL', model_field='other_settings', source='*')
    token_url = JsonSettingField(key='ACCESS_TOKEN_URL', model_field='other_settings', source='*')
    public_key = JsonSettingField(key='PUBLIC_KEY', model_field='other_settings', source='*')
    site = serializers.SlugRelatedField(slug_field='domain', queryset=Site.objects.all())
    enabled = serializers.BooleanField()
    client_id = serializers.CharField(source='key')
    secret = serializers.CharField()

    class Meta:
        model = OAuth2ProviderConfig
        exclude = [
            'backend_name',
            'enable_sso_id_verification',
            'icon_class',
            'icon_image',
            'max_session_length',
            'secondary',
            'send_to_registration_first',
            'send_welcome_email',
            'skip_email_verification',
            'skip_hinted_login_dialog',
            'skip_registration_form',
            'slug',
            'sync_learner_profile_data',
            'visible',
        ]

    def create(self, data):
        """Save Create instance with specified defaults for excluded fields"""
        # Requires sensible defaults
        data['backend_name'] = self.backend
        data['enable_sso_id_verification'] = False
        data['icon_class'] = 'fa-sign-in'
        data['icon_image'] = None
        data['max_session_length'] = None
        data['secondary'] = False
        data['send_to_registration_first'] = False
        data['send_welcome_email'] = False
        data['skip_email_verification'] = True
        data['skip_hinted_login_dialog'] = False
        data['skip_registration_form'] = True
        data['slug'] = self.backend
        data['sync_learner_profile_data'] = True
        data['visible'] = True

        data['other_settings'] = json.dumps({
            'AUTHORIZATION_URL': data.pop('auth_url'),
            'ACCESS_TOKEN_URL': data.pop('token_url'),
            'PUBLIC_KEY': data.pop('public_key'),
        })

        return self.Meta.model.objects.create(**data)

    def update(self, instance, data):
        return self.create(data)
