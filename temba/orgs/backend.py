from django.conf import settings
from django.contrib.auth.backends import ModelBackend
import requests
from temba.orgs.models import User, Org, OrgRole
from temba.orgs.models import Org
from django.db import transaction
from requests.exceptions import RequestException, Timeout
from time import sleep
import requests



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

MAX_RETRY = 3
RETRY_DELAY_SECONDS = 5




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
            # url = "http://localhost:8001/sms/auth/authy"

            data = {"email": username, "password": password}
            headers = {"Authorization": "Bearer " + settings.MISTA_ADMIN_TOKEN}

            for attempt in range(MAX_RETRY):
                try:
                    response = requests.post(url, headers=headers, json=data, timeout=30)
                    response.raise_for_status()  # Raise HTTPError for bad status codes
                    break  # Exit loop if successful
                except (RequestException, Timeout) as e:
                    print(f"Attempt {attempt+1}/{MAX_RETRY} failed:", e)
                    if attempt < MAX_RETRY - 1:  # If not the last attempt, wait before retrying
                        time.sleep(RETRY_DELAY_SECONDS)
            else:
                print("Max retries exceeded. Unable to authenticate.")
                return None

            if response.status_code == 200:
                # Authentication was successful
                access_token = response.json().get('access_token')
                if access_token:
                    payload = decode_jwt_token(access_token)
                    if payload:
                        account = payload.get('account')
                        if account:
                            check_and_update_subscription_status(payload)
                        if 'plan' in account and 'options' in account['plan']:
                            options = account['plan']['options']
                            if options:
                                json_data = json.loads(options)
                                flowartisan_access = json_data.get('flowartisan_access')
                                if flowartisan_access == "no":
                                    return None
                        else:
                            return None

                        # Check if the payload contains necessary information
                        if 'account' not in payload or 'plan' not in payload['account']:
                            return None

                        email = payload['account']['email']
                        try:
                            user = User.objects.get(username__iexact=email)
                        except User.DoesNotExist:
                            # Handle user creation
                            # Your existing code for user creation goes here
                            pass

                        return user

            else:
                print("API request failed with status code:", response.status_code)
                return None

        except Exception as e:
            print("An error occurred:", str(e))
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

