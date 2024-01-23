from django.conf import settings
from django.contrib.auth.backends import ModelBackend
import requests
from temba.orgs.models import User, Org, OrgRole
from django_redis import get_redis_connection
import logging
import jwt, json, redis
from jwt.exceptions import InvalidTokenError
from temba.contacts.models import ContactGroup
from temba.orgs.models import Org


logger = logging.getLogger(__name__)


class AuthenticationBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
       
        # redis_conn = get_redis_connection()

        # # Connect to Redis
        # redis_conn = redis.Redis(host='localhost', port=6379)

        # # Get the JSON object from Redis
        # json_str = redis_conn.execute_command('JSON.GET', 'user:session:5:20')
        # session = request.session.get('mistaio_session')

        # # Parse the JSON string into a Python object
        # json_obj = json.loads(json_str)    
       
        
        try:
            url = "https://api.mista.io/sms/auth/authy"
            data = {"email": username, "password": password}
           
            headers = {"Authorization": "Bearer 365|0K6iLq16mm5RpX0ydG1Q0l7Q8xXJF29qq4MbgAUR"}
            response = requests.post(url, headers=headers,json=data)
            
            if response.status_code == 200:
                # Authentication was successful
                access_token = response.json().get('access_token')
                

                if access_token:
                    payload = decode_jwt_token(access_token)
                    print(payload)
                    email = payload['account']['email']
                    try:
                        user = User.objects.get(username__iexact=email)
                    except User.DoesNotExist:
                        # create account from API
                        logger.info("User does not exist, registering one")
                        print("User does not exist, registering one")
                        email = payload['account']['email']
                        first_name = payload['account']['firstname']
                        last_name = payload['account']['lastname']
                        organization = payload['account']['organization']
                        user = User.objects.create_user(
                            username=email,
                            email=email,
                            first_name=first_name,
                            last_name=last_name,
                            password=None , # Password is handled by the authentication service
                        )
                        logger.info("New user created after call from auth service")
                        # create the Organisation
                        anonymous = User.objects.get(pk=1)  # the default anonymous user
                        org_data = dict(name=organization, created_by=anonymous,
                                        modified_by=anonymous,
                                        language="en-us",
                                        timezone=settings.USER_TIME_ZONE)

                        org = Org.objects.create(**org_data)
                        org.add_user(user, OrgRole.ADMINISTRATOR)
                        # create defaul contact group
                       
                        logger.info("New user Added to an organisation")
                        # create the default group
                        default_group = ContactGroup.create_system_groups(org)
                        if default_group:
                            logger.info("Default group created")
                        # # create sample flows
                        # sample_flows = Org.create_sample_flows(org,'https://api.mista.io/sms/flow/1')   
                        # if sample_flows:
                        #     logger.info("Sample flows created")     
                    return user
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

        # url = 'http://localhost:4000/user/auth/login'


def decode_jwt_token(token: str):
    secret = "Iz3IJVquJJYGQJ2sWnSPEB3e7PsZIHRrDUTehoIFDeebgqF8d73wJxxiVa2wPgbE"

    striped_bearer_token = strip_bearer_token(token)
    print(striped_bearer_token)

    try:

        payload = jwt.decode(striped_bearer_token, secret, algorithms=['HS256'])
        print(payload)
        return payload
    except InvalidTokenError:
        raise Exception("Invalid authentication credentials")


def strip_bearer_token(token):
    """
    Strips the "Bearer " text from a JWT token and returns only the token.

    Args:
        token_with_bearer (str): The JWT token with the "Bearer " text.

    Returns:
        str: The JWT token without the "Bearer " text.
    """
    if token.startswith("Bearer "):
        return token[7:]
    else:
        return token


class MyAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        url = "http://localhost:4000/user/auth/login"
        data = {"email": username, "password": password}
        response = requests.post(url, json=data)

        if response.status_code == 200:
            # Authentication was successful
            access_token = response.json().get('access_token')

            if access_token:
                payload = decode_jwt_token(access_token)

                try:
                    user = User.objects.get(email=payload['payload']['account']['email'])

                except User.DoesNotExist:
                    # User doesn't exist, create a new one
                    email = payload['payload']['account']['email']
                    first_name = payload['payload']['account']['firstname']
                    last_name = payload['payload']['account']['lastname']
                    organization = payload['payload']['account']['org']
                    user = User.objects.create_user(
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        password=None,  # Password is handled by the authentication service
                        organization=organization
                    )
                return user
            else:
                raise Exception("No access token found in response")
        elif response.status_code == 401:
            # Invalid credentials
            return None
        else:
            # Something went wrong
            raise Exception("Authentication failed: {}".format(response.status_code))