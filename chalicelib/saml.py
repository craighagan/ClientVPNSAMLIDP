import base64
import datetime
import logging
import re
import traceback
import uuid
import zlib
import xmltodict
from urllib.parse import quote, unquote
import defusedxml
import defusedxml.lxml
from signxml import XMLSigner, XMLVerifier
from .constants import IDP_NAME, cert


class SAMLData(object):
    saml_authn_prefixes = ["saml2", "saml"]

    def __init__(self):
        self._xml = None
        self._dict = None
        self._data_dict = None

    @property
    def xml(self):
        if self._xml is None:
            self._xml = self._parse_encoded_saml_to_xml()
        return self._xml

    @property
    def dict(self):
        if self._dict is None:
            self._dict = xmltodict.parse(self.xml)
        return self._dict

    @property
    def data_dict(self):
        if self._data_dict is None:
            self._data_dict = self._validate_saml_request_data(
                self._get_saml_request_data()
            )
        return self._data_dict

    @property
    def id(self):
        return self.data_dict.get("id")

    @property
    def date(self):
        return self.data_dict.get("date")

    @property
    def acs(self):
        return self.data_dict.get("acs")

    @staticmethod
    def get_utcnow():
        return datetime.datetime.utcnow()

    @staticmethod
    def get_endpoint_metadata(host):
        """
        generate and return the endpoint metadata document
        this is used for applications / service providers
        to configure themselves to talk to the endpoint
        """
        cleaned_up_cert = (
            cert.replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\n", "")
            .strip()
        )
        endpoint = f"https://{host}/api"
        valid_until = SAMLData.get_utcnow() + datetime.timedelta(days=365)
        # valid values for cache duration: http://www.datypic.com/sc/xsd/t-xsd_duration.html
        cache_duration = "PT1615129104S"

        return f"""<?xml version="1.0"?>
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="{valid_until.isoformat(timespec="seconds")}Z" cacheDuration="{cache_duration}" entityID="{IDP_NAME}">
      <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
              <ds:X509Certificate>{cleaned_up_cert}</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
              <ds:X509Certificate>{cleaned_up_cert}</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{endpoint}"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{endpoint}"/>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>
    """

    def _parse_encoded_saml_to_xml(self):
        """
        SAML requests from clientvpn can be base64 encoded
        and/or zlib compressed, hadle that and
        respond with a plain text xml blob
        """
        unquoted = unquote(self.saml_data).replace(" ", "")
        logging.debug("SAMLRequest: %s", unquoted)
        decoded = base64.b64decode(unquoted)
        logging.debug("decoded: %s", decoded)

        try:
            decompressed = zlib.decompress(decoded, -zlib.MAX_WBITS)
        except Exception:
            decompressed = decoded

        return decompressed.decode()

    def _encode_xml(self, compress=True):
        """
        encode saml xml, optionally
        compress it.
        """
        xml = xmltodict.unparse(self.saml_dict)

        if compress:
            obj = zlib.compressobj(wbits=zlib.MAX_WBITS)
            obj.compress(xml.encode())
            compressed = obj.flush()
            base64_encoded = base64.b64encode(compressed)
        else:
            base64_encoded = base64.b64encode(xml.encode())
        quoted = quote(base64_encoded)
        return quoted

    def _get_saml_request_data(self):
        """
        parse a saml request and retrieve a few
        basic pieces of information needed
        for responding to the request
        """

        result = {"id": "none", "date": "none", "destination": "none", "acs": "none"}

        try:

            for saml_request_prefix in self.saml_authn_prefixes:
                saml_request_key = f"{saml_request_prefix}p:AuthnRequest"
                logging.debug(
                    "looking at key %s vs %s", saml_request_key, self.dict.keys()
                )
                if saml_request_key in self.dict:
                    result = {
                        "id": self.dict[saml_request_key].get("@ID"),
                        "date": self.dict[saml_request_key].get("@IssueInstant"),
                        "acs": self.dict[saml_request_key].get(
                            "@AssertionConsumerServiceURL"
                        ),
                        "destination": self.dict[saml_request_key].get("@Destination"),
                        "issuer": self.dict[saml_request_key].get(
                            f"{saml_request_prefix}:Issuer"
                        ),
                    }
                    return result

            logging.error("Unable to parse SAML")
            logging.error(traceback.format_exc())
            return result

        except Exception as e:
            logging.error("Unable to parse SAML request")
            logging.error(str(e))
            logging.error(traceback.format_exc())
            return result

    def _validate_saml_request_data(self, data_dict):
        """
        Confirm that we have an expected AssertionCustomerServiceURL

        in future additional checks can be added
        """
        acs = data_dict.get("acs", "")
        if not acs.startswith(
            "https://self-service.clientvpn.amazonaws.com"
        ) and not acs.startswith("http://127.0.0.1"):
            raise RuntimeError("Invalid AssertionCustomerServiceURL presented")

        return data_dict

    @staticmethod
    def sign_saml_data(saml_data, cert, key):
        p = re.search("<samlp:Status>", saml_data).start()
        tmp_message = saml_data[:p]
        tmp_message = (
            tmp_message
            + '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"></ds:Signature>'
        )
        saml_data = tmp_message + saml_data[p:]
        saml_root = defusedxml.lxml.XML(saml_data.encode("ascii"))
        signed_saml_root = XMLSigner(
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"
        ).sign(saml_root, key=key, cert=cert)
        # verify the xml
        XMLVerifier().verify(signed_saml_root, x509_cert=cert).signed_xml
        signed_saml_root_str = defusedxml.lxml.tostring(
            signed_saml_root, encoding="unicode"
        )
        return signed_saml_root_str


class SAMLRequest(SAMLData):
    """
    model a saml request and provide
    the tools needed to react to it
    through login redirects and to build a response
    to the request
    """

    def __init__(self, encoded_saml_data):
        self.saml_data = encoded_saml_data
        super(SAMLRequest, self).__init__()

    @staticmethod
    def build_group_attributes(groups):
        """
        this assembles the memberOf attributes
        to relate the groups a user is a member of
        for AWS ClientVPN's consumption for authorization rules
        """

        output = ""
        for group in groups:
            output += '         <saml:AttributeValue xsi:type="xs:string">%(group)s</saml:AttributeValue>\n' % {
                "group": group,
            }
        return output

    def build_saml_response(self, user):
        """
        Construct the saml response
        """
        # https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html
        not_on_or_after = self.get_utcnow() + datetime.timedelta(days=370)
        not_before = self.get_utcnow() - datetime.timedelta(days=30)

        response_id = "_" + str(uuid.uuid4()).replace("-", "")
        assertion_id = "_" + str(uuid.uuid4()).replace("-", "")
        session_index = str(uuid.uuid4()).replace("-", "")

        saml_response = """<?xml version="1.0" encoding="utf-8"?>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%(response_id)s" InResponseTo="%(id)s" Version="2.0" IssueInstant="%(date)s" Destination="%(acs)s" >
      <saml:Issuer>%(idp_name)s</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="%(assertion_id)s" Version="2.0" IssueInstant="%(date)s">
        <saml:Issuer>%(idp_name)s</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%(email)s</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData InResponseTo="%(id)s" NotOnOrAfter="%(not_on_or_after_date)sZ" Recipient="%(acs)s"></saml:SubjectConfirmationData>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="%(not_before_date)sZ" NotOnOrAfter="%(not_on_or_after_date)sZ">
          <saml:AudienceRestriction>
            <saml:Audience>urn:amazon:webservices:clientvpn</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="%(date)s" SessionIndex="%(session_index)s">
          <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
          <saml:Attribute Name="NameID" NameFormat="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
            <saml:AttributeValue xsi:type="xs:string">%(email)s</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
            <saml:AttributeValue xsi:type="xs:string">%(first_name)s</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
            <saml:AttributeValue xsi:type="xs:string">%(last_name)s</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="PhoneNumber" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
            <saml:AttributeValue xsi:type="xs:string">%(phone_number)s</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
            <saml:AttributeValue xsi:type="xs:string">%(email)s</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="memberOf" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
            %(group_attributes)s
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>""" % {
            "response_id": response_id,
            "assertion_id": assertion_id,
            "idp_name": IDP_NAME,
            "id": self.id,
            "date": self.date,
            "acs": self.acs,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone_number": user.phone_number,
            "email": user.email,
            "group_attributes": self.build_group_attributes(user.groups),
            "session_index": session_index,
            "not_on_or_after_date": not_on_or_after.isoformat(timespec="seconds"),
            "not_before_date": not_before.isoformat(timespec="seconds"),
        }

        return saml_response

    def get_encoded_signed_saml_response(self, user, cert, key):
        """
        sign and encode the sam response
        """

        saml_response = self.build_saml_response(user)
        signed_response = self.sign_saml_data(saml_response, cert, key)
        encoded_response = base64.b64encode(bytes(signed_response, "utf-8")).decode(
            "utf-8"
        )
        return encoded_response

    def build_redirect_form(self, auth_handler, cert, key):
        """
        present a redirect form to the browser
        allowing the SAML response to be posted
        back to the AssertionCustomerServiceURL
        """

        encoded_saml_response = self.get_encoded_signed_saml_response(
            auth_handler.user, cert, key
        )
        html = f"""<html>
      <body onload="document.forms[0].submit()">
        <form method="POST" action="{self.acs}">
          <input type="hidden" name="SAMLResponse" value="{encoded_saml_response}">
          <input type="hidden" name="RelayState" value="{auth_handler.relay_state}">
        </form>
      </body>
    </html>
    """

        return html
