# originally from https://github.com/aws-samples/chalice-workshop/blob/master/code/media-query/04-s3-event/recordresources.py
from __future__ import print_function
import argparse
import json
import os

import boto3
from botocore import xform_name


def get_cognito_app_secret(stage, data):
    print("getting cognito client app information, this may take some time")
    cognito = boto3.client('cognito-idp')
    user_pool_id = data["stages"][stage]["environment_variables"]["USER_POOL_ID"]
    client_id = data["stages"][stage]["environment_variables"]["USER_POOL_CLIENT_ID"]
    res = cognito.describe_user_pool_client(UserPoolId=user_pool_id,
                                            ClientId=client_id)
    data["stages"][stage]["environment_variables"]["USER_POOL_CLIENT_SECRET"] = res["UserPoolClient"]["ClientSecret"]

    return data


def record_as_env_var(stack_name, stage):
    print("getting cloudformation stack outputs")
    cloudformation = boto3.client('cloudformation')
    response = cloudformation.describe_stacks(
        StackName=stack_name
    )
    outputs = response['Stacks'][0]['Outputs']

    with open(os.path.join('.chalice', 'config.json')) as f:
        data = json.load(f)
        data['stages'].setdefault(stage, {}).setdefault(
            'environment_variables', {}
        )
        for output in outputs:
            data['stages'][stage]['environment_variables'][
                _to_env_var_name(output['OutputKey'])] = output['OutputValue']

    # add additional data here
    data = get_cognito_app_secret(stage, data)

    with open(os.path.join('.chalice', 'config.json'), 'w') as f:
        serialized = json.dumps(data, indent=2, separators=(',', ': '))
        f.write(serialized + '\n')


def _to_env_var_name(name):
    return xform_name(name).upper()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--stage', default='dev')
    parser.add_argument('--stack-name', required=True)
    args = parser.parse_args()
    record_as_env_var(stack_name=args.stack_name, stage=args.stage)


if __name__ == '__main__':
    main()
