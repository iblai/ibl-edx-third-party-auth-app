""" Django REST Framework Serializers """

import json

from django.contrib.sites.models import Site
from rest_framework import serializers
from third_party_auth.models import OAuth2ProviderConfig, _PSA_OAUTH2_BACKENDS


class UserMappingSerializer(serializers.Serializer):  # pylint: disable=abstract-method
    """ Serializer for User Mapping """
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
    """ Serializer for OAuth2ProviderConfig's """

    changed_by = serializers.SlugRelatedField(slug_field='username', read_only=True)
    client_id = serializers.CharField(source='key')
    enabled = serializers.BooleanField()
    other_settings = serializers.JSONField()
    secret = serializers.CharField()
    site = serializers.SlugRelatedField(slug_field='domain', queryset=Site.objects.all())

    class Meta:
        model = OAuth2ProviderConfig
        exclude = [
            'backend_name',
            'enable_sso_id_verification',
            'icon_class',
            'icon_image',
            'key'
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

    def validate_backend_name(self, value):
        """Raise ValidationError if backend not active"""
        if value not in _PSA_OAUTH2_BACKENDS:
            raise serializers.ValidationError(
                '{} is not a valid backend'.format(value))
        return value

    def create(self, data):
        """Save Create instance with specified defaults for excluded fields"""
        backend_name = self.context['view'].kwargs['backend']
        self.validate_backend_name(backend_name)

        # Requires sensible defaults
        data['backend_name'] = backend_name
        data['changed_by'] = self.context['request'].user
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
        data['slug'] = backend_name
        data['sync_learner_profile_data'] = True
        data['visible'] = True

        data['other_settings'] = json.dumps(data['other_settings'])
        return self.Meta.model.objects.create(**data)

    def update(self, instance, data):
        return self.create(data)
