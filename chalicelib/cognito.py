import base64
import json
import os
import types
import boto3
from urllib.parse import quote, unquote
from .constants import COGNITO_DOMAIN, CLIENT_ID, USER_POOL_ID


class CognitoAuthResponseHandler(object):
    def __init__(self, access_token, state):
        self.access_token = access_token
        self.state = state

        self._state_dict = None
        self._client = None
        self._user_attributes = None
        self._user_groups = None
        self._user = None

    @staticmethod
    def redirect_cognito_login_form(cur_server, path, saml_request, relay):
        """
        Send the user to the cognito login form
        Cognito will authenticate the user
        and response with a post back with a bearer token
        """

        quoted_relay = relay
        if relay.startswith("{"):
            quoted_relay = quote(relay)

        state_dict = {"saml_request": saml_request, "relay": quoted_relay}
        state = quote(base64.b64encode(json.dumps(state_dict).encode()))
        cognito_link = CognitoAuthResponseHandler.build_cognito_login_link(
            cur_server, state
        )

        html = f"""<html>
    <head>
      <meta http-equiv="refresh" content="0; URL={cognito_link}" />
    </head>
    <body onload=window.location="{cognito_link}">
      <p>Redirecting to AWS Cognito, <a href="{cognito_link}">click here</a>.</p>
    </body>
    </html>
    """
        return html

    @staticmethod
    def build_cognito_login_link(callback_url, state):
        region = os.environ.get("AWS_REGION")

        cognito_link = f"https://{COGNITO_DOMAIN}.auth.{region}.amazoncognito.com/login?client_id={CLIENT_ID}&response_type=token&scope=aws.cognito.signin.user.admin&redirect_uri=https://{callback_url}/api/cognito/&state={state}"

        return cognito_link

    @staticmethod
    def build_cognito_login_redirect():
        """
        The response from cognito with a bearer
        token contains all of the critical bits
        after a hash (#), which isn't visible
        to chalice. Use javascript to adjust the url
        it out and redirect to the api

        This allows the system to see the bearer token
        """

        return """<html>
       <head>
          <script type="text/javascript">
        var new_location = "/api?" + window.location.hash.slice(1);
        window.location.href = new_location;

          </script>
       </head>
       <body onload=window.location=new_location >
          <p>you are being redirected to: <a><href="
    <script type="text/javascript">
    document.write(new_location)
    </script>
    ">
    <script type="text/javascript">
    document.write(new_location)
    </script>
    </a>
       </body>
    </html>
    """

    @property
    def client(self):
        if self._client is None:
            ses = boto3.session.Session()
            self._client = ses.client("cognito-idp")
        return self._client

    @property
    def state_dict(self):
        if self._state_dict is None:
            self._state_dict = json.loads(base64.b64decode(unquote(self.state)))
        return self._state_dict

    @property
    def saml_request(self):
        return self.state_dict.get("saml_request")

    @property
    def relay_state(self):
        return self.state_dict.get("relay")

    @property
    def user_attributes(self):
        """
        use the bearer token to get and
        build a dict of user attributes
        this will be used later to map
        into a saml response
        """
        if self._user_attributes is None:
            res = self.client.get_user(AccessToken=self.access_token)

            attributes = {}
            for attribute in res["UserAttributes"]:
                attributes[attribute["Name"]] = attribute["Value"]

            self._user_attributes = attributes
        return self._user_attributes

    @property
    def user_groups(self):
        """
        Groups don't appear to be directly
        provided as a user attribue,
        query the user pool directly to get
        a list of groups the user is a member of
        """
        if self._user_groups is None:
            # get user groups with attributes
            groups = []
            done = False
            next_token = None
            while not done:
                request = {
                    "UserPoolId": USER_POOL_ID,
                    "Username": self.user_attributes["email"],
                    "Limit": 60,
                }
                if next_token:
                    request["NextToken"] = next_token
                get_groups = self.client.admin_list_groups_for_user(**request)
                groups.extend(get_groups["Groups"])
                next_token = get_groups.get("NextToken", "")
                if not next_token:
                    done = True
            self._user_groups = groups
        return self._user_groups

    @property
    def user(self):
        """
        put everything together in a simple namespace object
        """
        if self._user is None:
            self._user = types.SimpleNamespace(
                username=self.user_attributes.get("email", ""),
                first_name=self.user_attributes.get("given_name", ""),
                last_name=self.user_attributes.get("family_name", ""),
                phone_number=self.user_attributes.get("phone_number", ""),
                email=self.user_attributes.get("email", ""),
                groups=[x["GroupName"] for x in self.user_groups],
            )
        return self._user
