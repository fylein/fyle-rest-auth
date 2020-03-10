"""
Fyle Authentication views
"""
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils.module_loading import import_string

from fylesdk import UnauthorizedClientError, NotFoundClientError, InternalServerError, WrongParamsError

from rest_framework.views import APIView, status
from rest_framework.response import Response

from .utils import AuthUtils
from .models import AuthToken


auth = AuthUtils()


class LoginView(APIView):
    """
    Login Using Fyle Account
    """
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        """
        Login using authorization code
        """
        try:
            authorization_code = request.data.get('code')

            if not authorization_code:
                return Response(
                    {
                        'message': 'authorization code / request body not found'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

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

            return Response(
                data=tokens,
                status=status.HTTP_200_OK,
            )

        except UnauthorizedClientError as e:
            return Response(
                {
                    'message': 'Invalid Authorization Code',
                    'response': e.response
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        except NotFoundClientError as e:
            return Response(
                {
                    'message': 'Fyle Application not found',
                    'response': e.response
                },
                status=status.HTTP_404_NOT_FOUND
            )
        except WrongParamsError as e:
            return Response(
                {
                    'message': 'Some of the parameters are wrong',
                    'response': e.response
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except InternalServerError as e:
            return Response(
                {
                    'message': 'Wrong/Expired Authorization code',
                    'response': e.response
                },
                status=status.HTTP_401_UNAUTHORIZED
            )


class RefreshView(APIView):
    """
    Refresh Access Token
    """
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')

            if not refresh_token:
                return Response(
                    {
                        'message': 'refresh token / request body not found'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            tokens = auth.refresh_access_token(refresh_token)

            employee_info = auth.get_fyle_user(refresh_token)
            users = get_user_model()

            user = users.objects.filter(email=employee_info['employee_email'],
                                        user_id=employee_info['user_id']).first()

            if not user:
                return Response(
                    {
                        'message': 'User record not found, please login'
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )

            auth_token = AuthToken.objects.get(user=user)
            auth_token.refresh_token = refresh_token
            auth_token.save()

            serializer = import_string(settings.FYLE_REST_AUTH_SERIALIZERS['USER_DETAILS_SERIALIZER'])
            tokens['user'] = serializer(user).data
            tokens['refresh_token'] = refresh_token

            return Response(
                data=tokens,
                status=status.HTTP_200_OK
            )

        except UnauthorizedClientError as e:
            return Response(
                {
                    'message': 'Invalid Refresh Token',
                    'response': e.response
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        except NotFoundClientError as e:
            return Response(
                {
                    'message': 'Fyle Application not found',
                    'response': e.response
                },
                status=status.HTTP_404_NOT_FOUND
            )
        except WrongParamsError as e:
            return Response(
                {
                    'message': 'Some of the parameters are wrong',
                    'response': e.response
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except InternalServerError as e:
            return Response(
                {
                    'message': 'Something went wrong. Please try again in sometime',
                    'response': e.response
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
