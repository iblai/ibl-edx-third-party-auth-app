import logging

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
    data = {
        "user_id": user_id,
        "platform_key": platform_key,
    }
    logger.info(f"Linking user {user_id} to platform {platform_key}")
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
