from django.conf import settings
from django.contrib.auth.backends import ModelBackend
import requests
from temba.orgs.models import User, Org, OrgRole
from temba.orgs.models import Org
from django.db import transaction


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
        try:
            url = "https://api.mista.io/sms/auth/authy"
            #url = "http://localhost:8001/sms/auth/authy"

            data = {"email": username, "password": password}
            headers = {"Authorization": "Bearer " + settings.MISTA_ADMIN_TOKEN}
            response = requests.post(url, headers=headers, json=data)

            if response.status_code == 200:
                # Authentication was successful
                access_token = response.json().get('access_token')

                if access_token:
                    payload = decode_jwt_token(access_token)
                    if payload:
                        check_and_update_subscription_status(payload)

                        account = payload.get('account')
                        if account:
                            plan = account.get('plan')
                            if plan:
                                options = plan.get('options')
                                if options:
                                    try:
                                        json_data = json.loads(options)
                                        flowartisan_access = json_data.get('flowartisan_access')
                                        print(flowartisan_access)
                                    except json.JSONDecodeError:
                                        print("Error decoding JSON data in options.")
                                else:
                                    print("'options' not found in payload.")
                            else:
                                print("'plan' not found in payload.")
                        else:
                            print("'account' not found in payload.")
                    else:
                        print("Payload not found.")

                    # Ensure necessary keys are present before accessing
                    if payload and 'account' in payload and 'plan' in payload['account'] and 'options' in payload['account']['plan']:
                        if 'flowartisan_access' not in payload['account']['plan']['options'] or payload['account']['plan']['options']['flowartisan_access'] == "no":
                            return None  # Authentication failed

                        # Access user data from payload and create the user
                        email = payload['account']['email']
                        try:
                            user = User.objects.get(username__iexact=email)
                        except User.DoesNotExist:
                            # Create user
                            user = User.objects.create_user(
                                username=email,
                                email=email,
                                first_name=payload['account']['firstname'],
                                last_name=payload['account']['lastname'],
                                password=None  # Password is handled by the authentication service
                            )

                            # Create organization and associate user with it
                            org = Org.objects.create(name=payload['account']['organization'], timezone=settings.USER_TIME_ZONE, language=settings.DEFAULT_LANGUAGE, flow_languages='{eng}')
                            org.add_user(user, OrgRole.ADMINISTRATOR)

                            # Additional tasks
                            analytics.identify(user, brand=request.branding, org=org)
                            analytics.track(user, "temba.org_signup", properties=dict(org=org.name))                     
                            switch_to_org(request, org)
                            org.initialize(sample_flows=True)

                            login(request, user)
                            self.get_success_url()

                        return user
                    else:
                        print("Necessary keys are missing in the payload.")
                        return None
                else:
                    print("Access token not found in the response.")
                    return None
            else:
                print("Authentication failed with status code:", response.status_code)
                return None
        except Exception as e:
            print("An error occurred during authentication:", str(e))
            return None

        

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
        print(payload)
        return payload
    except jwt.exceptions.InvalidTokenError:
        return None  # Return None instead of raising an exception for invalid credentials

       
    except InvalidTokenError:
        raise Exception("Invalid authentication credentials")


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

