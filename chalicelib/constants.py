import os


IDP_NAME = "ClientVPNSAMLIDP"
USER_POOL_ID = os.environ.get("USER_POOL_ID")
CLIENT_ID = os.environ.get("USER_POOL_CLIENT_ID")
CLIENT_SECRET = os.environ.get("USER_POOL_CLIENT_SECRET")
COGNITO_DOMAIN = os.environ.get("USER_POOLDOMAIN_ID")
NO_CERT_MESSAGE = """Generate your certificate by running this command:

openssl req -x509 -nodes -days 3000 -newkey rsa:1024 -keyout chalicelib/mykey.pem -out chalicelib/mycert.pem

"""
#
# get a proper cert if you can, make a self-signed if not
# openssl req -x509 -nodes -days 3000 -newkey rsa:1024 -keyout mykey.pem -out mycert.pem
#


def read_file_contents(filename, message="no such file"):
    local_filename = os.path.join(os.path.dirname(__file__), filename)

    if not os.path.exists(local_filename):
        message = f"can't open file {local_filename} " + message
        raise RuntimeError(message)

    with open(local_filename) as f:
        return f.read()


cert = read_file_contents("mycert.pem", NO_CERT_MESSAGE)

key = read_file_contents("mykey.pem", NO_CERT_MESSAGE)
