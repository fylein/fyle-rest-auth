"""
Authentication utils
"""
import json
from typing import Dict

import requests

from fylesdk import FyleSDK, UnauthorizedClientError, NotFoundClientError, InternalServerError, WrongParamsError

from django.conf import settings


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

        return self.post(url=self.token_url, body=api_data)

    def get_fyle_user(self, refresh_token: str) -> Dict:
        """
        Get Fyle user detail
        """
        connection = FyleSDK(
            base_url=self.base_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            refresh_token=refresh_token
        )

        employee_detail = connection.Employees.get_my_profile()['data']

        return employee_detail

    @staticmethod
    def post(url, body):
        """
        Send Post request
        """
        response = requests.post(url, data=body)

        if response.status_code == 200:
            return json.loads(response.text)

        elif response.status_code == 401:
            raise UnauthorizedClientError('Wrong client secret or/and refresh token', response.text)

        elif response.status_code == 404:
            raise NotFoundClientError('Client ID doesn\'t exist', response.text)

        elif response.status_code == 400:
            raise WrongParamsError('Some of the parameters were wrong', response.text)

        elif response.status_code == 500:
            raise InternalServerError('Internal server error', response.text)
