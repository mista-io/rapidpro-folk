from django.conf import settings
from django.contrib.auth.backends import ModelBackend
import requests
from temba.orgs.models import User, Org, OrgRole
from temba.orgs.models import Org
from django.db import transaction
from requests.exceptions import RequestException, Timeout
from time import sleep
import time


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
            #i will implement this later
            return "%s?start" % reverse("public.public_welcome")

    def pre_process(self, request, *args, **kwargs):
        # if our brand doesn't allow signups, then redirect to the homepage instead
        if "signups" not in request.branding.get("features", []):  # pragma: needs cover
            return HttpResponseRedirect(reverse("public.public_index"))

        else:
            return super().pre_process(request, *args, **kwargs)
    def authenticate(self, request, username=None, password=None, **kwargs):
        retry_attempts = 3  # Number of retry attempts
        retry_delay = 5  # Delay between retry attempts in seconds

        try:
            url = "https://api.mista.io/sms/auth/authy"
            data = {"email": username, "password": password}
            headers = {"Authorization": "Bearer " + settings.MISTA_ADMIN_TOKEN}

            for attempt in range(retry_attempts):
                try:
                    response = requests.post(url, headers=headers, json=data, timeout=30)
                    if response.status_code == 200:
                        # Authentication was successful
                        access_token = response.json().get('access_token')

                        if access_token:
                            payload = decode_jwt_token(access_token)
                            if payload:
                                account = payload.get('account')
                                if account:
                                    check_and_update_subscription_status(payload)
                                else:
                                    return None
                            else:
                                return None

                            if account and 'plan' in account and 'options' in account['plan']:
                                options = account['plan']['options']
                                if options:
                                    json_data = json.loads(options)
                                    flowartisan_access = json_data.get('flowartisan_access')
                                    if flowartisan_access == "no":
                                        return None
                            else:
                                return None

                            email = account.get('email')
                            try:
                                user = User.objects.get(username__iexact=email)
                            except User.DoesNotExist:
                                # create account from API
                                logger.info("User does not exist, registering one")

                                first_name = account.get('firstname')
                                last_name = account.get('lastname')
                                organization = account.get('organization')

                                required_fields = [first_name, last_name, organization]
                                if any(field is None for field in required_fields):
                                    # Handle the case where one or more required fields are missing
                                    return None

                                # Instead of creating user directly, use create_user to handle password hashing
                                user = User.objects.create_user(
                                    username=email,
                                    email=account.get('email'),
                                    first_name=first_name,
                                    last_name=last_name,
                                    password=None  # Password is handled by the authentication service
                                )

                                anonymous = User.objects.get(pk=1)  # the default anonymous user
                                org_data = dict(name=organization, created_by=anonymous, modified_by=anonymous,
                                                timezone=settings.USER_TIME_ZONE, language=settings.DEFAULT_LANGUAGE,
                                                flow_languages='{eng}')

                                org = Org.objects.create(**org_data)

                                org.add_user(user, OrgRole.ADMINISTRATOR)
                                logger.info("New user added to an organization")
                                logger.info(org)

                                analytics.identify(user, brand=request.branding, org=org)
                                analytics.track(user, "temba.org_signup", properties=dict(org=org.name))
                                switch_to_org(request, org)
                                org.initialize(sample_flows=True)

                                login(request, user)
                                self.get_success_url()

                            return user
                    else:
                        print("API request failed with status code:", response.status_code)

                except RequestException as e:
                    print("Attempt", attempt + 1, "failed:", e)
                    if attempt < retry_attempts - 1:
                        time.sleep(retry_delay)
                        continue
                    else:
                        return None

        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a non-existing user (#20760).
            User().set_password(password)
  

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

