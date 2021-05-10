

CALLBACK_URL="$(chalice url)cognito"
REGION=FIXME

aws cloudformation --region ${REGION} update-stack \
    --stack-name Cognito  \
    --capabilities CAPABILITY_NAMED_IAM \
    --template-body file://cloudformation/cognito-cloudformation.yml \
    --parameters ParameterKey=CallbackURL,ParameterValue=${CALLBACK_URL}
