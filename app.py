from chalice import Chalice, Response
import logging
import traceback

from urllib.parse import parse_qsl
from chalicelib.saml import SAMLRequest
from chalicelib.cognito import CognitoAuthResponseHandler
from chalicelib.constants import cert, key

app = Chalice(app_name="ClientVPNSAMLIDP")
app.debug = False  # turn of if needed


logging.basicConfig(level=logging.INFO)

HEADERS = {
    "Content-Type": "text/html",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


#
# remove if you are debugging responses
#
# @app.route(
#    "/introspect",
#    methods=["GET", "POST"],
#    content_types=["application/x-www-form-urlencoded", "application/json"],
# )
# def introspect():
#    return app.current_request.to_dict()


@app.route(
    "/metadata",
    methods=["GET", "POST"],
    content_types=["application/x-www-form-urlencoded", "application/json"],
)
def metadata():
    request = app.current_request

    host = request.headers.get("host", "")

    return Response(
        SAMLRequest.get_endpoint_metadata(host),
        status_code=200,
        headers={"Content-Type": "text/xml"},
    )


@app.route(
    "/cognito",
    methods=["GET", "POST"],
    content_types=["application/x-www-form-urlencoded", "application/json"],
)
def cognito():
    return Response(
        CognitoAuthResponseHandler.build_cognito_login_redirect(),
        status_code=200,
        headers={"Content-Type": "text/html"},
    )


@app.route(
    "/",
    methods=["GET", "POST"],
    content_types=["application/x-www-form-urlencoded", "application/json"],
)
def index():
    request = app.current_request
    query_params = {}

    try:
        try:
            post_params = dict(parse_qsl(request.raw_body.decode()))
        except Exception:
            post_params = {}

        if request.query_params:
            query_params = request.query_params

        relay_state = post_params.get("RelayState", query_params.get("RelayState", ""))
        saml_request = post_params.get(
            "SAMLRequest", query_params.get("SAMLRequest", "")
        )
        saml_response = post_params.get(
            "SAMLResponse", query_params.get("SAMLResponse", "")
        )
        host = request.headers.get("host", "")
        path = request.context.get("path", "")

        state = query_params.get("state")
        access_token = query_params.get("access_token")

        if access_token is not None and state is not None:
            auth_handler = CognitoAuthResponseHandler(access_token, state)

            saml_obj = SAMLRequest(auth_handler.saml_request)

            return Response(
                saml_obj.build_redirect_form(auth_handler, cert, key),
                status_code=200,
                headers=HEADERS,
            )

        elif saml_request and not saml_response and not post_params:
            body = CognitoAuthResponseHandler.redirect_cognito_login_form(
                host, path, saml_request, relay_state
            )
            return Response(
                body,
                status_code=200,
                headers=HEADERS,
            )

        body = "Bad Request"
        return Response(body, status_code=400, headers=HEADERS)

    except Exception as e:
        if app.debug:
            body = "<pre>An error occurred:\n\n%s\n\n%s</pre>" % (
                str(e),
                traceback.format_exc(),
            )
            return Response(body, status_code=500, headers=HEADERS)

        body = "Something went wrong"
        return Response(body, status_code=500, headers=HEADERS)
