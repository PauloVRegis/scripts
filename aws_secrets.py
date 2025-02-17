#!/usr/bin/env python3
from distutils.command.config import config
import os
import sys

import argparse
import time
import boto3
from botocore.exceptions import ClientError

# -------------------------------------------------------------------- main ---

def copy_secrets(config):
    dry_run = config["global.dryrun"]
    cleanup = config["global.cleanup"]

    if dry_run:
        print(f"dry run enabled")
    src, dst = compile_config(config)

    if cleanup:
        print(f"clean up enabled")
        print('Starting the cleanUp of destination entries...')
        dst_current_secrets = pull_secrets(dst["aws.session"])
        dst_remove_secrets(dst["aws.session"], dst_current_secrets, dry_run)
        print('Destination secret manager has been cleared...')

        if not dry_run:
            print('Waiting 30 seconds for secrets manager to purge deleted entries...')
            time.sleep(30)

    src_secrets = pull_secrets(src["aws.session"])
    push_secrets(dst["aws.session"], src_secrets, dry_run)

# --------------------------------------------------------------------- fns ---

def dst_remove_secrets(session, secrets, dry_run):
    for secret in secrets:
        result = {"action": "deleted", "name": secret["Name"], "profile_name": session.profile_name}
        if not dry_run:
            delete_sm_secret(session, secret)
        print(f'{result["action"]:<10}{result["name"]}')

def pull_secrets(session):
    secrets = list_sm_secrets(session)
    for secret in secrets:
        secret_value = get_sm_secret_value(session, secret["Name"])
        yield secret_value


def push_secret(session, secret, dry_run):
    current_secret = get_sm_secret_value(session, secret["Name"])
    result = {"action": "nochange", "name": secret["Name"]}
    if current_secret is None:
        result["action"] = "created"
        if not dry_run:
            create_sm_secret(session, secret)
    elif current_secret["SecretString"] != secret["SecretString"]:
        result["action"] = "updated"
        if not dry_run:
            put_sm_secret_value(session, secret)

    print(f'{result["action"]:<10}{result["name"]}')

def push_secrets(session, secrets, dry_run):
    for secret in secrets:
        push_secret(session, secret, dry_run)

# --------------------------------------------------------------------- aws ---

def delete_sm_secret(session, secret):
    try:
        sm = session.client("secretsmanager")
        params = {"SecretId": secret["Name"], "ForceDeleteWithoutRecovery": True}
        sm.delete_secret(**params)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            pass  # ignore if secret is missing
        else:
            raise err

def create_sm_secret(session, secret):
    sm = session.client("secretsmanager")
    params = {"Name": secret["Name"], "ForceOverwriteReplicaSecret": True}
    if "SecretString" in secret:
        params["SecretString"] = secret["SecretString"]
    else:
        params["SecretBinary"] = secret["SecretBinary"]
    response = sm.create_secret(**params)
    return response

def restore_sm_secret(session, name):
    sm = session.client("secretsmanager")
    sm.restore_secret(SecretId=name)


def get_sm_secret_value(session, name):
    sm = session.client("secretsmanager")
    secret = None
    try:
        secret = sm.get_secret_value(SecretId=name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            pass  # ignore if secret is missing
        elif err.response["Error"]["Code"] == "InvalidRequestException":
            restore_sm_secret(session, name)
            secret = get_sm_secret_value(session, name)
        else:
            raise err
    return secret or None


def list_sm_secrets(session):
    sm = session.client("secretsmanager")
    pages = sm.get_paginator("list_secrets").paginate()
    for page in pages:
        secrets = page["SecretList"]
        for secret in secrets:
            if not "DeletedDate" in secret:
                yield secret


def put_sm_secret_value(session, secret):
    sm = session.client("secretsmanager")
    params = {"SecretId": secret["Name"]}
    if "SecretString" in secret:
        params["SecretString"] = secret["SecretString"]
    else:
        params["SecretBinary"] = secret["SecretBinary"]
    response = sm.put_secret_value(**params)
    return response


# ------------------------------------------------------------------ config ---

def get_params_aws_credentials(configType):
    credentials_params = None
    if configType["aws.profile"] != None:
        credentials_params = {"region_name": configType["aws.region"], "profile_name": configType["aws.profile"]}
    else:
        credentials_params = {"region_name": configType["aws.region"],"aws_access_key_id": configType["aws.access_key"], "aws_secret_access_key": configType["aws.access_secret"], "aws_session_token": configType["aws.session_token"]}

    return credentials_params

def compile_config(config):
    src = config["src"]
    dst = config["dst"]

    src["aws.session"] = boto3.Session(
        **get_params_aws_credentials(src)
    )
    dst["aws.session"] = boto3.Session(
        **get_params_aws_credentials(dst)
    )

    return src, dst


def get_default_config():
    config = {
        "global.dryrun": int(os.environ.get("DRY_RUN", "1")) == 1,
        "src": {
            "aws.region": os.environ.get("SRC_AWS_REGION", "sa-east-1"),
            "aws.profile": os.environ.get("SRC_AWS_PROFILE", "DEVOPS-ODIN"),
        },
        "dst": {
            "aws.region": os.environ.get("DST_AWS_REGION", "sa-east-1"),
            "aws.profile": os.environ.get("DST_AWS_PROFILE"),
        },
    }
    return config


# ---------------------------------------------------------------- handlers ---


def script_handler(args):
    config = get_default_config()

    argsParser = argparse.ArgumentParser(fromfile_prefix_chars='@')

    argsParser.add_argument('--source-profile', dest='SourceProfile', type=str,
                        help='Name of the source profile to connect to AWS source account. It must be configured using AWS CLI (aws configure)')

    argsParser.add_argument('--dest-profile', dest='DestProfile', type=str,
                        help='Name of the destination profile to connect to AWS target account. It must be configured using AWS CLI (aws configure)')

    argsParser.add_argument('--source-accesskey', dest='SourceAccessKey', type=str,
                        help='Source\'s Access Key to connect to Source Account')

    argsParser.add_argument('--source-accesssecret', dest='SourceAccessSecret', type=str,
                        help='Source\'s Access Key Secret to connect to Source Account')

    argsParser.add_argument('--source-sessiontoken', dest='SourceSessionToken', type=str,
                        help='Source\'s Access Token to connect to Destination Account')

    argsParser.add_argument('--dest-accesskey', dest='DestAccessKey', type=str,
                        help='Destination\'s Access Key to connect to Destination Account')

    argsParser.add_argument('--dest-accesssecret', dest='DestAccessSecret', type=str,
                        help='Destination\'s Access Key Secret to connect to Destination Account')

    argsParser.add_argument('--dest-sessiontoken', dest='DestSessionToken', type=str,
                        help='Destination\'s Access Token to connect to Destination Account')

    argsParser.add_argument('--dryrun', dest='DryRun', action='store_true', help='Indicates whether the execution should not commit the changes')
    
    argsParser.add_argument('--cleanup', dest='CleanUp', action='store_true', help='Indicates whether the destination account should be cleaned up before creating the entries')

    # Execute parse_args()
    appArguments = argsParser.parse_args()

    # same account copy:  script.py <src_profile> <dst_profile> [nodryrun]
    config["src"]["aws.profile"] = appArguments.SourceProfile
    config["dst"]["aws.profile"] = appArguments.DestProfile

    config["src"]["aws.access_key"] = appArguments.SourceAccessKey
    config["src"]["aws.access_secret"] = appArguments.SourceAccessSecret
    config["src"]["aws.session_token"] = appArguments.SourceSessionToken

    config["dst"]["aws.access_key"] = appArguments.DestAccessKey
    config["dst"]["aws.access_secret"] = appArguments.DestAccessSecret
    config["dst"]["aws.session_token"] = appArguments.DestSessionToken

    config["global.dryrun"] = appArguments.DryRun
    config["global.cleanup"] = appArguments.CleanUp

    copy_secrets(config)


def lambda_handler(event, context):
    raise Exception("Not implemented yet!")

if __name__ == "__main__":
    script_handler(sys.argv)