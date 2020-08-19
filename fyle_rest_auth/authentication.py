import json
from typing import Dict

import requests

from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.cache import cache

from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from .models import AuthToken

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

        user = self.validate_token(access_token_string=access_token_string)

        try:
            user = User.objects.get(email=user['email'], user_id=user['user_id'])
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
    def validate_token(access_token_string: str) -> Dict:
        """
        Validate the access token
        :param access_token_string:
        :return:
        """
        if access_token_string:
            access_token_tokenizer = access_token_string.split(' ')
            unique_key_generator = access_token_tokenizer[1].split('.')

            if not access_token_tokenizer or len(access_token_tokenizer) != 2 or access_token_tokenizer[0] != 'Bearer':
                raise exceptions.AuthenticationFailed('Invalid access token structure')

            fyle_base_url = settings.FYLE_BASE_URL
            my_profile_uri = '{0}/api/tpa/v1/employees/my_profile'.format(fyle_base_url)

            api_headers = {'Authorization': '{0}'.format(access_token_string)}

            email_unique_key = 'email_{0}'.format(unique_key_generator[2])
            user_unique_key = 'user_{0}'.format(unique_key_generator[2])

            email = cache.get(email_unique_key)
            user = cache.get(user_unique_key)

            if not (email and user):
                cache.delete_many([email_unique_key, user_unique_key])
                response = requests.get(my_profile_uri, headers=api_headers)

                if response.status_code == 200:
                    result = json.loads(response.text)['data']

                    cache.set(email_unique_key, result['employee_email'], settings.CACHE_EXPIRY)
                    cache.set(user_unique_key, result['user_id'], settings.CACHE_EXPIRY)

                    return {
                        'email': result['employee_email'],
                        'user_id': result['user_id']
                    }

            elif email and user:
                return {
                    'email': email,
                    'user_id': user
                }

        raise exceptions.AuthenticationFailed('Invalid access token')
