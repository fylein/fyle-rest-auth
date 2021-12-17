"""
Authentication utils
"""
from typing import Dict

from django.conf import settings

from .helpers import post_request


class AuthUtils:
    """
    Authentication utility functions
    """
    def __init__(self):
        self.base_url = settings.FYLE_BASE_URL
        self.token_url = settings.FYLE_TOKEN_URI
        self.client_id = settings.FYLE_CLIENT_ID
        self.client_secret = settings.FYLE_CLIENT_SECRET

    def generate_fyle_refresh_token(self, authorization_code: str) -> Dict:
        """
        Get refresh token from authorization code
        """
        api_data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': authorization_code
        }

        return self.post(url=self.token_url, body=api_data)

    def refresh_access_token(self, refresh_token: str) -> Dict:
        """
        Refresh access token using refresh token
        """
        api_data = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token
        }

        return post_request(self.token_url, api_data)


    @staticmethod
    def get_origin_address(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[-1].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
