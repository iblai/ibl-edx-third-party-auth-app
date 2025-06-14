"""Django REST Framework Serializers"""

import json

from common.djangoapps.third_party_auth.models import (
    _PSA_OAUTH2_BACKENDS,
    OAuth2ProviderConfig,
)
from django.contrib.sites.models import Site
from rest_framework import serializers


class OAuthProviderSerializer(serializers.ModelSerializer):
    """Serializer for OAuth2ProviderConfig's"""

    changed_by = serializers.SlugRelatedField(slug_field="username", read_only=True)
    client_id = serializers.CharField(source="key")
    enabled = serializers.BooleanField()
    other_settings = serializers.JSONField()
    secret = serializers.CharField()
    site = serializers.SlugRelatedField(
        slug_field="domain", queryset=Site.objects.all()
    )

    class Meta:
        model = OAuth2ProviderConfig
        exclude = [
            "backend_name",
            "enable_sso_id_verification",
            "icon_class",
            "icon_image",
            "key",
            "max_session_length",
            "secondary",
            "send_to_registration_first",
            "send_welcome_email",
            "skip_email_verification",
            "skip_hinted_login_dialog",
            "skip_registration_form",
            "slug",
            "sync_learner_profile_data",
            "visible",
        ]

    def validate_other_settings(self, value):
        """Raise ValidationError if specific entries not in other_settings

        This required values come from
        serializer.context['required_other_settings']
        """
        keys = set(value.keys())
        required = set(self.context.get("required_other_settings", []))
        missing = required - keys
        if missing:
            raise serializers.ValidationError(
                "Missing required fields in other_settings: {}".format(
                    ", ".join(missing)
                )
            )
        return value

    def validate_backend_name(self, value):
        """Raise ValidationError if backend not active"""
        if value not in _PSA_OAUTH2_BACKENDS:
            raise serializers.ValidationError("{} is not a valid backend".format(value))
        return value

    def create(self, data):
        """Save Create instance with specified defaults for excluded fields"""

        backend_name = self.context["view"].kwargs["backend"]
        self.validate_backend_name(backend_name)

        # Requires sensible defaults
        data["backend_name"] = backend_name
        data["changed_by"] = self.context["request"].user
        data["enable_sso_id_verification"] = False
        data["icon_class"] = "fa-sign-in"
        data["icon_image"] = None
        data["max_session_length"] = None
        data["secondary"] = False
        data["send_to_registration_first"] = False
        data["send_welcome_email"] = False
        data["skip_email_verification"] = True
        data["skip_hinted_login_dialog"] = False
        data["skip_registration_form"] = True
        data["slug"] = backend_name
        data["sync_learner_profile_data"] = False
        data["visible"] = True

        # Ensure item is saved as proper json string in other_settings text field
        # edx relies on `clean` to do this normally but only called in admin
        data["other_settings"] = json.dumps(data["other_settings"])
        return self.Meta.model.objects.create(**data)

    def to_representation(self, instance):
        """Make sure other_settings is always JSON

        b/c other_settings is actually a TextField on the model, when a GET is
        requested, it returns the content as a string instead of actual JSON.

        This checks the current return type and makes sure it's always JSON

        Not sure why they didn't use the jsonfield.JSONField; maybe wasn't
        known at time of creation.
        """
        rep = super(OAuthProviderSerializer, self).to_representation(instance)
        settings = rep["other_settings"]
        # Make sure empty string can be loaded as empty json
        if not settings.strip():
            settings = "{}"
        if isinstance(settings, str):
            rep["other_settings"] = json.loads(settings)
        return rep
