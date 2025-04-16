import logging

from django.conf import settings
from ibl_request_router.api.manager import manager_api_request

logger = logging.getLogger(__name__)


def link_user_to_platform(user_id, platform_key):
    """
    Links a user to a platform using the Manager API.

    Args:
    user_id (str): The ID of the user to link.
    platform_key (str): The platform key to link the user to.

    Returns:
    bool: True if the linking was successful (status code 200 or 201), False otherwise.
    """
    endpoint_path = "/core/users/platforms/"  # The function manager_api_request already appends /api to the Manager URLs

    # First check if the link already exists
    try:
        check_response = manager_api_request(
            "GET", f"{endpoint_path}?user_id={user_id}&platform_key={platform_key}"
        )
        link_exists = (
            check_response
            and check_response.status_code == 200
            and check_response.json().get("results", [])
        )

        # If user creation is disabled and link doesn't exist, block new link creation
        if (
            getattr(settings, "SOCIAL_AUTH_DISABLE_USER_CREATION", False)
            and not link_exists
        ):
            logger.warning(
                f"New user platform linking disabled: SOCIAL_AUTH_DISABLE_USER_CREATION is True. "
                f"Skipping new link creation for user {user_id} to platform {platform_key}"
            )
            return False

        # If link already exists, return True
        if link_exists:
            logger.info(
                f"Link already exists for user {user_id} to platform {platform_key}"
            )
            return True

    except Exception as e:
        logger.warning(
            f"Error checking existing link for user {user_id} to platform {platform_key}: {str(e)}. "
            "Proceeding with link attempt."
        )

    # Proceed with creating the link
    data = {
        "user_id": user_id,
        "platform_key": platform_key,
    }
    logger.info(f"Creating new link for user {user_id} to platform {platform_key}")
    try:
        response = manager_api_request("POST", endpoint_path, data=data)
        logger.info(f"Response: {response}")

        if response and response.status_code in [200, 201]:
            status_message = (
                "already existed" if response.status_code == 200 else "created"
            )
            logger.info(
                f"Successfully linked user {user_id} to platform {platform_key} "
                f"(status: {status_message})"
            )
            return True
        else:
            logger.error(
                f"Failed to link user {user_id} to platform {platform_key}. "
                f"Status code: {response.status_code if response else 'No response'}"
            )
            return False
    except Exception as e:
        logger.exception(
            f"Error linking user {user_id} to platform {platform_key}: {str(e)}"
        )
        return False
