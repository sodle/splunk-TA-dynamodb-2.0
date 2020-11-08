import boto3


def get_aws_session(aws_access_key_id, aws_secret_access_key, aws_assume_role_name):
    """
    Create a boto3 session from either an access key/secret, an assumed role, or instance role.

    :param aws_access_key_id:
    :param aws_secret_access_key:
    :param aws_assume_role_name:
    :type aws_access_key_id: str, optional
    :type aws_secret_access_key: str, optional
    :type aws_assume_role_name: str, optional
    :return session:
    :rtype: boto3.session.Session
    """
    access_key_id = aws_access_key_id
    secret_access_key = aws_secret_access_key
    session_token = None

    if aws_assume_role_name is not None and len(aws_assume_role_name) > 0:
        sts = boto3.client('sts', aws_access_key_id=access_key_id,
                           aws_secret_access_key=secret_access_key, aws_session_token=session_token)
        role = sts.assume_role(RoleArn=aws_assume_role_name,
                               RoleSessionName="splunk-TA-dynamodb")
        access_key_id = role.AccessKeyId
        secret_access_key = role.SecretAccessKey
        session_token = role.SessionToken

    return boto3.session.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key,
                                 aws_session_token=session_token)
