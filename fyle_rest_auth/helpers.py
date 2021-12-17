import json
from typing import Dict

import requests

from rest_framework.exceptions import ValidationError

from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils.module_loading import import_string

from .utils import AuthUtils
from .models import AuthToken

auth = AuthUtils()


def validate_code_and_login(request):
    authorization_code = request.data.get('code')
    try:
        if not authorization_code:
            raise ValidationError('authorization code not found')

        tokens = auth.generate_fyle_refresh_token(authorization_code=authorization_code)

        employee_info = get_fyle_admin(tokens['access_token'], auth.get_origin_address(request))
        users = get_user_model()

        user, _ = users.objects.get_or_create(
            user_id=employee_info['data']['user']['id'],
            email=employee_info['data']['user']['email']
        )

        AuthToken.objects.update_or_create(
            user=user,
            defaults={
                'refresh_token': tokens['refresh_token']
            }
        )

        serializer = import_string(settings.FYLE_REST_AUTH_SERIALIZERS['USER_DETAILS_SERIALIZER'])
        tokens['user'] = serializer(user).data

        return tokens

    except Exception as error:
        raise ValidationError(error)


def validate_and_refresh_token(request):
    refresh_token = request.data.get('refresh_token')
    try:
        if not refresh_token:
            raise ValidationError('refresh token not found')

        tokens = auth.refresh_access_token(refresh_token)

        employee_info = get_fyle_admin(tokens['access_token'], auth.get_origin_address(request))
        users = get_user_model()

        user = users.objects.filter(
            email=employee_info['data']['user']['email'],user_id=employee_info['data']['user']['id']
        ).first()

        if not user:
            raise ValidationError('User record not found, please login')

        auth_token = AuthToken.objects.get(user=user)
        auth_token.refresh_token = refresh_token
        auth_token.save()

        serializer = import_string(settings.FYLE_REST_AUTH_SERIALIZERS['USER_DETAILS_SERIALIZER'])
        tokens['user'] = serializer(user).data
        tokens['refresh_token'] = refresh_token

        return tokens

    except Exception as error:
        raise ValidationError(error)


def get_cluster_domain(access_token: str, origin_address: str = None) -> str:
    """
    Get cluster domain name from fyle
    :param access_token: (str)
    :return: cluster_domain (str)
    """
    cluster_api_url = '{0}/oauth/cluster/'.format(settings.FYLE_BASE_URL)

    return post_request(cluster_api_url, {}, access_token, origin_address)['cluster_domain']


def get_fyle_admin(access_token: str, origin_address: str = None) -> Dict:
    """
    Get user profile from fyle
    :param access_token: (str)
    :return: user_profile (dict)
    """
    cluster_domain = get_cluster_domain(access_token, origin_address)

    profile_api_url = '{}/platform/v1beta/spender/my_profile'.format(cluster_domain)
    employee_detail = get_request(profile_api_url, access_token, origin_address)

    if 'ADMIN' in employee_detail['data']['roles']:
        return employee_detail
    else:
        raise Exception('User is not an admin')


def post_request(url, body, access_token: str = None, origin_address: str = None) -> Dict:
    """
    Create a HTTP post request.
    """
    api_headers = {
        'content-type': 'application/json',
        'X-Forwarded-For': origin_address
    }

    if access_token:
        api_headers['Authorization'] = 'Bearer {0}'.format(access_token)

    response = requests.post(
        url,
        headers=api_headers,
        data=body
    )

    if response.status_code == 200:
        return json.loads(response.text)
    else:
        raise Exception(response.text)


def get_request(url, access_token, origin_address: str = None):
    """
    Create a HTTP get request.
    """
    api_headers = {
        'Authorization': 'Bearer {0}'.format(access_token),
        'X-Forwarded-For': origin_address
    }

    response = requests.get(
        url,
        headers=api_headers
    )

    if response.status_code == 200:
        return json.loads(response.text)
    else:
        raise Exception(response.text)
