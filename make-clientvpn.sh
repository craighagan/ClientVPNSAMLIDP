

ENDPOINT_CERTIFICATE_ARN="FIXME"
CALLBACK_URL=$(chalice url)
FEDERATION_XML=$(curl --silent ${CALLBACK_URL}/metadata |tr -d '\n' |sed s/\"/\\\\\"/g )
REGION=FIXME
VPC_ID=FIXME
PUBLIC_SUBNET1_ID=FIXME

cat - <<EOF > cloudformation/clientvpn-parameters.json
[
  {
    "ParameterKey": "CallbackURL",
    "ParameterValue": "${CALLBACK_URL}"
  },
  {
    "ParameterKey": "VPCId",
    "ParameterValue": "${VPC_ID}"
  },
  {
    "ParameterKey": "PublicSubnet1",
    "ParameterValue": "${PUBLIC_SUBNET1_ID}"
  },
  {
    "ParameterKey": "FederationXML",
    "ParameterValue": "${FEDERATION_XML}"
  },
  {
    "ParameterKey": "EndpointCertificateArn",
    "ParameterValue": "${ENDPOINT_CERTIFICATE_ARN}"
  }
]
EOF


aws cloudformation --region ${REGION} create-stack \
    --stack-name ClientVPN  \
    --capabilities CAPABILITY_NAMED_IAM \
    --template-body file://cloudformation/clientvpn-cloudformation.yml \
    --parameters file://cloudformation/clientvpn-parameters.json
