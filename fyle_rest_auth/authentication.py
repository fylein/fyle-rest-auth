import json
import requests

import requests_cache

from django.contrib.auth import get_user_model
from django.conf import settings

from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from .models import AuthToken

requests_cache.install_cache('demo_cache', backend='sqlite', expire_after=1200)

User = get_user_model()


class FyleJWTAuthentication(BaseAuthentication):
    """
    Fyle Authentication class
    """
    def authenticate(self, request):
        """
        Authentication function
        """
        access_token_string = self.get_header(request)

        user_email = self.validate_token(access_token_string=access_token_string)

        try:
            user = User.objects.get(email=user_email)
            AuthToken.objects.get(user=user)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('User not found for this token')
        except AuthToken.DoesNotExist:
            raise exceptions.AuthenticationFailed('Login details not found for the user')

        return user, None

    @staticmethod
    def get_header(request) -> str:
        """
        Extracts the header containing the JSON web token from the given
        request.
        """
        header = request.META.get('HTTP_AUTHORIZATION')

        return header

    @staticmethod
    def validate_token(access_token_string: str) -> str:
        """
        Validate the access token
        :param access_token_string:
        :return:
        """
        if access_token_string:
            access_token_tokenizer = access_token_string.split(' ')

            if not access_token_tokenizer or len(access_token_tokenizer) != 2 or access_token_tokenizer[0] != 'Bearer':
                raise exceptions.AuthenticationFailed('Invalid access token structure')

            fyle_base_url = settings.FYLE_BASE_URL
            my_profile_uri = '{0}/api/tpa/v1/employees/my_profile'.format(fyle_base_url)

            api_headers = {'Authorization': '{0}'.format(access_token_string)}

            response = requests.get(my_profile_uri, headers=api_headers)

            if response.status_code == 200:
                result = json.loads(response.text)['data']
                return result['employee_email']

        raise exceptions.AuthenticationFailed('Invalid access token')
