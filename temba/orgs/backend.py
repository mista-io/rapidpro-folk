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
from temba.utils import analytics, get_anonymous_user, json, languages, str_to_bool
from django.contrib.auth.views import LoginView as AuthLoginView
from smartmin.users.views import Login, UserUpdateForm
from django.contrib.auth import authenticate, login, logout
from django.urls import reverse, reverse_lazy
from django.http import HttpResponseRedirect, HttpResponse






logger = logging.getLogger(__name__)


class AuthenticationBackend(ModelBackend):
    def get_success_url(self):
            return "%s?start" % reverse("public.public_welcome")

    def pre_process(self, request, *args, **kwargs):
        # if our brand doesn't allow signups, then redirect to the homepage
        if "signups" not in request.branding.get("features", []):  # pragma: needs cover
            return HttpResponseRedirect(reverse("public.public_index"))

        else:
            return super().pre_process(request, *args, **kwargs)


    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            url = "https://api.mista.io/sms/auth/authy"
            data = {"email": username, "password": password}
            headers = {"Authorization": "Bearer " + settings.MISTA_ADMIN_TOKEN}
            response = requests.post(url, headers=headers, json=data)

            if response.status_code == 200:
                # Authentication was successful
                access_token = response.json().get('access_token')

                if access_token:
                    payload = decode_jwt_token(access_token)

                    if payload is None:
                        return None  # Authentication failed, return None instead of raising an exception

                    email = payload['account']['email']
                    try:
                        user = User.objects.get(username__iexact=email)
                    except User.DoesNotExist:
                        # create account from API
                        logger.info("User does not exist, registering one")

                        first_name = payload['account']['firstname']
                        last_name = payload['account']['lastname']
                        organization = payload['account']['organization']

                        # Instead of creating user directly, use create_user to handle password hashing
                        user = User.objects.create_user(
                            username=email,
                            email=payload['account']['email'],
                            first_name=first_name,
                            last_name=last_name,
                            password=None  # Password is handled by the authentication service
                        )

                        # create the Organization
                        anonymous = User.objects.get(pk=1)  # the default anonymous user
                        org_data = dict(name=organization, created_by=anonymous, modified_by=anonymous, 
                                        timezone=settings.USER_TIME_ZONE, language=settings.DEFAULT_LANGUAGE,flow_languages='{eng}')

                        org = Org.objects.create(**org_data)
                       
                        

                        org.add_user(user, OrgRole.ADMINISTRATOR)
                        logger.info("New user added to an organization")
                        logger.info(org)

                        # Additional tasks specific to your application
                        #self.object = org  # Assuming self.object is used elsewhere in your code
                        analytics.identify(user, brand=request.branding, org=org)
                        analytics.track(user, "temba.org_signup", properties=dict(org=org.name))                     
                        switch_to_org(request, org)
                        org.initialize(sample_flows=True)

                        login(request, user)
                        self.get_success_url()

                    return user
                else:
                    return None
        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a non-existing user (#20760).
            User().set_password(password)

    # The rest of the AuthenticationBackend remains unchanged...

       

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
        #print(f"check this###########{payload}", payload)
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

