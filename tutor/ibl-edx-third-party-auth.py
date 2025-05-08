from tutor import hooks

hooks.Filters.ENV_PATCHES.add_item(
    (
        "common-env-features",
        """
"ENABLE_THIRD_PARTY_AUTH": {{IBL_EDX.IBL_EDX_BASE_OAUTH_SSO_BACKEND.ENABLE_THIRD_PARTY_AUTH}}

""",
    )
)
