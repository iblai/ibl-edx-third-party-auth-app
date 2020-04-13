""" Django REST Framework Serializers """

import json

from django.contrib.sites.models import Site
from openedx.core.djangoapps.site_configuration.models import SiteConfiguration
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
            'key',
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

    def validate_other_settings(self, value):
        """Raise ValidationError if specific entries not in other_settings

        This required values come from
        serializer.context['required_other_settings']
        """
        keys = set(value.keys())
        required = set(self.context.get('required_other_settings', []))
        missing = required - keys
        if missing:
            raise serializers.ValidationError(
                'Missing required fields in other_settings: {}'.format(
                    ', '.join(missing)
                )
            )
        return value

    def validate_backend_name(self, value):
        """Raise ValidationError if backend not active"""
        if value not in _PSA_OAUTH2_BACKENDS:
            raise serializers.ValidationError(
                '{} is not a valid backend'.format(value))
        return value

    def validate_cms_site(self, value):
        try:
            return Site.objects.get(domain=value)
        except Site.DoesNotExist:
            raise serializers.ValidationError(
                "cms_site with domain {} does not exist".format(value))

    def validate_cms_subdomain(self, lms_site, cms_site):
        """Raise ValidationError if CMS is not a subdomain of the LMS"""
        lms_domain = lms_site.domain
        cms_domain = cms_site.domain
        lms = '.' + lms_domain
        if not cms_domain.endswith(lms):
            raise serializers.ValidationError(
                "cms_site must be a subdomain of site. "
                "site: {} :: cms_site: {}".format(lms_domain, cms_domain)
            )

    def create(self, data):
        """Save Create instance with specified defaults for excluded fields"""

        backend_name = self.context['view'].kwargs['backend']
        self.validate_backend_name(backend_name)

        cms_site = data['other_settings'].get('CMS_SITE')
        cms_site = self.validate_cms_site(cms_site)
        self.validate_cms_subdomain(data['site'], cms_site)

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
        data['sync_learner_profile_data'] = False
        data['visible'] = True

        # Ensure item is saved as proper json string in other_settings text field
        # edx relies on `clean` to do this normally but only called in admin
        data['other_settings'] = json.dumps(data['other_settings'])

        # Update session cookie domain for lms and cms - they should match
        cookie_domain = '.' + data['site'].domain

        self._update_cookie_domain_for_site(data['site'], cookie_domain)
        self._update_cookie_domain_for_site(cms_site, cookie_domain)

        return self.Meta.model.objects.create(**data)

    def _update_cookie_domain_for_site(self, site, cookie_domain):
        """Set the SESSION_COOKIE_DOMAIN for site"""
        config = SiteConfiguration.objects.get(site=site)
        config.values['SESSION_COOKIE_DOMAIN'] = cookie_domain
        config.save()

    def to_representation(self, instance):
        """Make sure other_settings is always JSON

        b/c other_settings is actually a TextField on the model, when a GET is
        requested, it returns the content as a string instead of actual JSON.

        This checks the current return type and makes sure it's always JSON

        Not sure why they didn't use the jsonfield.JSONField; maybe wasn't
        known at time of creation.
        """
        rep = super(OAuthProviderSerializer, self).to_representation(instance)
        settings = rep['other_settings']
        # Make sure empty string can be loaded as empty json
        if not settings.strip():
            settings = u"{}"
        if isinstance(settings, (str, unicode)):
            rep['other_settings'] = json.loads(settings)
        return rep
