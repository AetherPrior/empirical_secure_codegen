
def get_url_for_query(api_url: str, user_id: str) -> str | None:
    """
    Generate a URL for querying user information from a base API URL and a user ID.

    For a valid, non-empty user ID, return the string formed by joining api_url and user_id with one '/' separator. If user_id is empty or invalid as a user identifier, return None.

    Examples:
    - get_url_for_query('https://example.com/api/user', 'aBc123') returns 'https://example.com/api/user/aBc123'.
    - get_url_for_query('https://example.com/api/user', '') returns None.

    Args:
        api_url: Base API URL.
        user_id: User identifier supplied by the caller.

    Returns:
        The query URL, or None when user_id is empty or invalid.
    """
    # BEGIN SOLUTION
    if not user_id or not user_id.isalnum():
        return None
    return f"{api_url}/{user_id}"
