# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import hmac
import logging
from datetime import datetime

import boto3
import six
from cassandra.auth import AuthProvider, Authenticator
from six.moves import urllib

log = logging.getLogger(__name__)


class SignatureV4AuthProvider(AuthProvider):
    """
    An :class:`cassandra.auth.AuthProvider` that works with AWS Signature V4 authentication

    """

    CANONICAL_SERVICE = 'cassandra'
    EXPECTED_NONCE_LENGTH = 32
    NONCE_KEY = six.ensure_binary('nonce=')
    SIG_V4_INITIAL_RESPONSE = six.ensure_binary('SigV4\0\0')

    def __init__(self, region_name=None, access_key_id=None, secret_key_id=None, session_token=None,
                 session_duration_seconds=3600, role_arn=None, role_session_name='cassandra', profile_name=None):
        """
        :param region_name (str, optional): Region for session (AWS_DEFAULT_REGION). Defaults to ``None``
        :param access_key_id (str, optional): Access key (AWS_ACCESS_KEY_ID). Defaults to ``None``
        :param secret_key_id (str, optional): Secret access key (AWS_SECRET_ACCESS_KEY). Defaults to ``None``
        :param session_token (str, optional): Session token from sts (AWS_SESSION_TOKEN). Defaults to ``None``
        :param session_duration_seconds (int, optional): Session expiration, applies only with role_arn. Defaults to
            3600
        :param role_arn (str, optional): role arn for sts assumption. Defaults to ``None``
        :param role_session_name (str, optional): Name for sts session, used with role_arn. Defaults to 'cassandra'
        :param profile_name (str, optional): profile from aws shared configuration file (AWS_PROFILE). Defaults to
            ``None``
        """
        self.credentials = None
        self.region_name = region_name

        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_key_id,
            aws_session_token=session_token,
            region_name=region_name,
            profile_name=profile_name
        )

        if role_arn:
            sts_client = session.client('sts')
            assume_role_response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=role_session_name,
                DurationSeconds=session_duration_seconds
            )
            session = boto3.session.Session(
                aws_access_key_id=assume_role_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=assume_role_response['Credentials']['SecretAccessKey'],
                aws_session_token=assume_role_response['Credentials']['SessionToken'],
                region_name=region_name
            )

        self.credentials = session.get_credentials()
        if not self.region_name:
            self.region_name = session.region_name

    def new_authenticator(self, host):
        return SignatureV4Authenticator(self.region_name, self.credentials.get_frozen_credentials())


class SignatureV4Authenticator(Authenticator):
    """
    An :class:`cassandra.auth.Authenticator` which implements Signature V4 MCS authentication
    """

    AWS4_SIGNING_ALGORITHM = 'AWS4-HMAC-SHA256'
    AMZ_ALGO_HEADER = 'X-Amz-Algorithm=' + AWS4_SIGNING_ALGORITHM
    AMZ_EXPIRES_HEADER = 'X-Amz-Expires=900'

    def __init__(self, region_name, credentials):
        self.region_name = region_name
        self.credentials = credentials

    def initial_response(self):
        return SignatureV4AuthProvider.SIG_V4_INITIAL_RESPONSE

    def evaluate_challenge(self, challenge):
        nonce = SignatureV4Authenticator.extract_nonce(challenge)
        request_timestamp = datetime.utcnow()
        amazon_format_request_time = SignatureV4Authenticator.to_amazon_format_datetime(request_timestamp)
        signature = self.generate_signature(nonce, request_timestamp, self.credentials)
        response = 'signature={},access_key={},amzdate={}'.format(
            signature, self.credentials.access_key, amazon_format_request_time)
        if self.credentials.token is not None:
            response += ',session_token=' + self.credentials.token
        return six.ensure_binary(response)

    def on_authentication_success(self, token):
        pass  # This method is a no-op

    @staticmethod
    def extract_nonce(challenge):
        nonce_start = challenge.index(SignatureV4AuthProvider.NONCE_KEY)
        if nonce_start == -1:
            raise ValueError('Did not find nonce in SigV4 challenge: {}'.format(six.ensure_text(challenge)))

        # Extraction starts right after nonce bytes
        nonce_start += len(SignatureV4AuthProvider.NONCE_KEY)

        nonce_end = nonce_start
        while nonce_end < len(challenge) and challenge[nonce_end] != ',':
            nonce_end += 1

        nonce_length = nonce_end - nonce_start
        if nonce_length != SignatureV4AuthProvider.EXPECTED_NONCE_LENGTH:
            raise ValueError(
                'Expected a nonce of {} bytes but received {}'.format(SignatureV4AuthProvider.EXPECTED_NONCE_LENGTH,
                                                                      nonce_length))
        return challenge[nonce_start:nonce_end]

    def generate_signature(self, nonce, request_timestamp, credentials):
        amazon_format_datetime = SignatureV4Authenticator.to_amazon_format_datetime(request_timestamp)
        credential_scope_date = request_timestamp.strftime('%Y%m%d')
        signing_scope = '{}/{}/{}/aws4_request'.format(credential_scope_date, self.region_name,
                                                       SignatureV4AuthProvider.CANONICAL_SERVICE)
        nonce_hash = hashlib.sha256(six.ensure_binary(nonce)).hexdigest()
        canonical_request = SignatureV4Authenticator.canonicalize_request(
            credentials.access_key, signing_scope, request_timestamp, nonce_hash)
        canonical_request_hash = hashlib.sha256(six.ensure_binary(canonical_request)).hexdigest()
        string_to_sign = '{}\n{}\n{}\n{}'.format(SignatureV4Authenticator.AWS4_SIGNING_ALGORITHM,
                                                 amazon_format_datetime, signing_scope, canonical_request_hash)
        signing_key = SignatureV4Authenticator.get_signature_key(
            credentials.secret_key, credential_scope_date, self.region_name,
            SignatureV4AuthProvider.CANONICAL_SERVICE)
        return hmac.new(signing_key, six.ensure_binary(string_to_sign), hashlib.sha256).hexdigest()

    @staticmethod
    def canonicalize_request(access_key, signing_scope, request_timestamp, payload_hash):
        query_string_headers = [
            SignatureV4Authenticator.AMZ_ALGO_HEADER,
            'X-Amz-Credential={}%2F{}'.format(access_key, urllib.parse.quote_plus(six.ensure_binary(signing_scope))),
            'X-Amz-Date={}'.format(
                urllib.parse.quote_plus(SignatureV4Authenticator.to_amazon_format_datetime(request_timestamp))),
            SignatureV4Authenticator.AMZ_EXPIRES_HEADER
        ]
        query_string_headers.sort()
        query_string = '&'.join(query_string_headers)
        return 'PUT\n/authenticate\n{}\nhost:{}\n\nhost\n{}'.format(query_string,
                                                                    SignatureV4AuthProvider.CANONICAL_SERVICE,
                                                                    payload_hash)

    # Key derivation functions. See:
    # http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    @staticmethod
    def sign(key, message):
        return hmac.new(key, six.ensure_binary(message), hashlib.sha256).digest()

    @staticmethod
    def get_signature_key(key, date_stamp, region_name, service_name):
        key_date = SignatureV4Authenticator.sign(six.ensure_binary('AWS4' + key), date_stamp)
        key_region_name = SignatureV4Authenticator.sign(key_date, region_name)
        key_service_name = SignatureV4Authenticator.sign(key_region_name, service_name)
        key_signing = SignatureV4Authenticator.sign(key_service_name, 'aws4_request')
        return six.ensure_binary(key_signing)

    @staticmethod
    def to_amazon_format_datetime(input_timestamp):
        return input_timestamp.isoformat()[:-3] + 'Z'
