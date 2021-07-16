from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils.module_loading import import_string

from .utils import AuthUtils
from .models import AuthToken

auth = AuthUtils()


def validate_code_and_login(authorization_code: str):
    try:
        if not authorization_code:
            raise AuthenticationFailed('authorization code not found')

        tokens = auth.generate_fyle_refresh_token(authorization_code=authorization_code)

        employee_info = auth.get_fyle_user(tokens['refresh_token'])
        users = get_user_model()

        user, _ = users.objects.get_or_create(
            user_id=employee_info['user_id'],
            email=employee_info['employee_email']
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
        raise AuthenticationFailed(error)

def validate_and_refresh_token(refresh_token: str):
    try:
        if not refresh_token:
            raise AuthenticationFailed('refresh token not found')

        tokens = auth.refresh_access_token(refresh_token)

        employee_info = auth.get_fyle_user(refresh_token)
        users = get_user_model()

        user = users.objects.filter(email=employee_info['employee_email'], user_id=employee_info['user_id']).first()

        if not user:
            raise AuthenticationFailed('User record not found, please login')

        auth_token = AuthToken.objects.get(user=user)
        auth_token.refresh_token = refresh_token
        auth_token.save()

        serializer = import_string(settings.FYLE_REST_AUTH_SERIALIZERS['USER_DETAILS_SERIALIZER'])
        tokens['user'] = serializer(user).data
        tokens['refresh_token'] = refresh_token

        return tokens

    except Exception as error:
        raise AuthenticationFailed(error)
