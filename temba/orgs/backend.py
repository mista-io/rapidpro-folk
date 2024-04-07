from django.conf import settings
from django.contrib.auth.backends import ModelBackend
import requests
from temba.orgs.models import User, Org, OrgRole
from temba.orgs.models import Org
from django.db import transaction
from requests.exceptions import RequestException, Timeout
from time import sleep
from django_redis import get_redis_connection
import logging
import jwt
import json
import redis
from jwt.exceptions import InvalidTokenError
from django.shortcuts import render, redirect
from temba.orgs.views import switch_to_org
from temba.orgs.models import Org
from temba.utils import analytics, get_anonymous_user, json, languages, str_to_bool
from django.contrib.auth.views import LoginView as AuthLoginView
from smartmin.users.views import Login, UserUpdateForm
from django.contrib.auth import authenticate, login, logout
from django.urls import reverse, reverse_lazy
from django.http import HttpResponseRedirect, HttpResponse





logger = logging.getLogger(__name__)


class AuthenticationBackend(ModelBackend):
    def get_success_url(self):
        # I will implement this later
        return "%s?start" % reverse("public.public_welcome")

    def pre_process(self, request, *args, **kwargs):
        # If our brand doesn't allow signups, then redirect to the homepage instead
        if "signups" not in request.branding.get("features", []):
            return HttpResponseRedirect(reverse("public.public_index"))
        else:
            return super().pre_process(request, *args, **kwargs)

    def authenticate(self, request, username=None, password=None, **kwargs):
        tokenx = get_token_from_redis(username)

        # Get vtoken from the request
        user_vtoken = request.POST.get('vtoken')
        redis_vtoken = get_vtoken_from_redis(username)

        if tokenx and redis_vtoken == user_vtoken:
            logger.info(f"Successfully logged in user '{username}' using token from Redis.")
            print("Token found in Redis")
            # Token found in Redis, decode it and process authentication
            payload = decode_jwt_token(tokenx)
            if payload:
                account = payload.get('account')
                if account:
                    check_and_update_subscription_status(payload)

                    # Ensure that options is a dictionary before using .get()
                    if account and 'plan' in account and 'options' in account['plan']:
                        options = account['plan']['options']
                        if options:
                            json_data = json.loads(options)
                            flowartisan_access = json_data.get('flowartisan_access')
                            print(flowartisan_access)
                            if flowartisan_access == "no":
                                return None
                    else:
                        return None

                    try:
                        if payload is None or 'account' not in payload or 'flowartisan_access' not in payload['account']['plan']['options'] or flowartisan_access == "no":
                            return None  # Authentication failed, return None instead of raising an exception

                    except KeyError:
                        print("Either 'account', 'plan', or 'options' key is missing in the payload")

                email = payload['account']['email']
                try:
                    user = User.objects.get(username__iexact=email)
                except User.DoesNotExist:
                    # Create account from API
                    logger.info("User does not exist, registering one")

                    # All required fields are present
                    first_name = payload['account']['firstname']
                    last_name = payload['account']['lastname']
                    organization = payload['account']['organization']

                    required_fields = [first_name, last_name, organization]
                    missing_fields = [field for field in required_fields if not field]
                    if missing_fields:
                        # Handle the case where one or more required fields are missing
                        return None
                    # Proceed with registration

                    # Instead of creating user directly, use create_user to handle password hashing
                    user = User.objects.create_user(
                        username=email,
                        email=payload['account']['email'],
                        first_name=first_name,
                        last_name=last_name,
                        password=None  # Password is handled by the authentication service
                    )

                    # Create the Organization
                    anonymous = User.objects.get(pk=1)  # the default anonymous user
                    org_data = dict(name=organization, created_by=anonymous, modified_by=anonymous,
                                    timezone=settings.USER_TIME_ZONE, language=settings.DEFAULT_LANGUAGE,
                                    flow_languages='{eng}')

                    org = Org.objects.create(**org_data)

                    # Add user to organization as administrator
                    org.add_user(user, OrgRole.ADMINISTRATOR)
                    logger.info("New user added to an organization")
                    logger.info(org)

                    # Additional tasks specific to your application
                    analytics.identify(user, brand=request.branding, org=org)
                    analytics.track(user, "temba.org_signup", properties=dict(org=org.name))
                    switch_to_org(request, org)
                    org.initialize(sample_flows=True)

                    # Log user in
                    login(request, user)
                    self.get_success_url()

                return user
            else:
                return None
        else:
            return None


        # try:
        #     url = "https://api.mista.io/sms/auth/authy"
        #     #url = "http://localhost:8001/sms/auth/authy"

        #     data = {"email": username, "password": password}
        #     headers = {"Authorization": "Bearer " + settings.MISTA_ADMIN_TOKEN}
        #     # Wait some seconds until the url api responds 
        #     try :
        #         response = requests.post(url, headers=headers, json=data,timeout=30) 
        #     except requests.exceptions.RequestException as e:
        #         print(e)
        #         return None

        #     if response.status_code == 200:
        #         # Authentication was successful
        #         access_token = response.json().get('access_token')
        #         print("access_token generated from api.mista.io")

        #         if access_token:
        #             payload = decode_jwt_token(access_token)
        #             if payload:
        #                 account = payload['account']
        #                 if account:
        #                     check_and_update_subscription_status(payload)

        #                 if account and 'plan' in account and 'options' in account['plan']:
        #                     options = account['plan']['options']
        #                     if options:
        #                         json_data = json.loads(options)
        #                         flowartisan_access = json_data.get('flowartisan_access')
        #                         print(flowartisan_access)
        #                         if flowartisan_access == "no":
        #                             return None
        #                 else:
        #                     return None

        #                 email = payload['account']['email']
        #                 try:
        #                     user = User.objects.get(username__iexact=email)
        #                 except User.DoesNotExist:
        #                     # Create account from API
        #                     logger.info("User does not exist, registering one")

        #                     # All required fields are present
        #                     first_name = payload['account']['firstname']
        #                     last_name = payload['account']['lastname']
        #                     organization = payload['account']['organization']

        #                     required_fields = [first_name, last_name, organization]
        #                     missing_fields = [field for field in required_fields if not field]
        #                     if missing_fields:
        #                         # Handle the case where one or more required fields are missing
        #                         return None

        #                     # Proceed with registration
        #                     # Instead of creating user directly, use create_user to handle password hashing
        #                     user = User.objects.create_user(
        #                         username=email,
        #                         email=payload['account']['email'],
        #                         first_name=first_name,
        #                         last_name=last_name,
        #                         password=None  # Password is handled by the authentication service
        #                     )

        #                     # Create the Organization
        #                     anonymous = User.objects.get(pk=1)  # the default anonymous user
        #                     org_data = dict(name=organization, created_by=anonymous, modified_by=anonymous, 
        #                                     timezone=settings.USER_TIME_ZONE, language=settings.DEFAULT_LANGUAGE,flow_languages='{eng}')

        #                     org = Org.objects.create(**org_data)

        #                     # Add user to organization as administrator
        #                     org.add_user(user, OrgRole.ADMINISTRATOR)
        #                     logger.info("New user added to an organization")
        #                     logger.info(org)

        #                     # Additional tasks specific to your application
        #                     analytics.identify(user, brand=request.branding, org=org)
        #                     analytics.track(user, "temba.org_signup", properties=dict(org=org.name))                     
        #                     switch_to_org(request, org)
        #                     org.initialize(sample_flows=True)

        #                     # Log user in
        #                     login(request, user)
        #                     self.get_success_url()

        #                 return user
        #             else:
        #                 print("Payload is None")
        #                 return None
        #     else:
        #         print("Authentication failed")
        #         return None
        # except User.DoesNotExist:
        #     # Run the default password hasher once to reduce the timing
        #     # difference between an existing and a non-existing user (#20760).
        #     User().set_password(password)


       

    def get_user(self, user_id):
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:  # pragma: no cover
            return None
        return user if self.user_can_authenticate(user) else None
    


def decode_jwt_token(token: str):
    secret = settings.MISTA_JWT_SECRET

    stripped_bearer_token = strip_bearer_token(token)

    try:
        payload = jwt.decode(stripped_bearer_token, secret, algorithms=['HS256'])
        return payload
    except jwt.exceptions.InvalidTokenError:
        return None  # Return None instead of raising an exception for invalid credentials

       
   

def strip_bearer_token(token):
    """
    Strips the "Bearer " text from a JWT token and returns only the token.

    Args:
        token (str): The JWT token with or without the "Bearer " text.

    Returns:
        str: The JWT token without the "Bearer " text.
    """
    if token.startswith("Bearer "):
        return token[7:]
    else:
        return token

def check_and_update_subscription_status(payload):
    if payload is None:
        return None

    org_email = payload.get('account', {}).get('email')
    if org_email:
        try:
            org = User.objects.get(username=org_email).orgs.first()
        except User.DoesNotExist:
            # Handle the case where the user doesn't exist
            org = None
        print(org)
        
        status = payload['account']['subscription']['status']
        print(status)
        if status == "active" and org:
            org.unsuspend()
            return True
        elif org:
            org.suspend()
            return False
        else:
            # Handle the case where org is None
            return None
    else:
        # Handle the case where org email is not provided in payload
        return None

def get_token_from_redis(username):
    try:
        r = get_redis_connection()
        token_key = f'token-{username}'
        token = r.get(token_key)
        return token.decode('utf-8') if token else None
    except Exception as e:
        # Handle exceptions, such as Redis connection errors
        print(e)
        return None
def get_vtoken_from_redis(username):
    try:
        r = get_redis_connection()
        vtoken_key = f'vtoken-{username}'
        vtoken = r.get(vtoken_key)
        return vtoken.decode('utf-8') if vtoken else None
    except Exception as e:
        # Handle exceptions, such as Redis connection errors
        print(e)
        return None