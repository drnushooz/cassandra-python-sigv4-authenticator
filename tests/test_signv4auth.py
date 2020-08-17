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
import six

from sigv4auth import *

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class TestSignatureV4Authenticator(unittest.TestCase):
    def test_nonce_extraction(self):
        test_nonce = '1234abcd1234abcd1234abcd1234abcd'
        self.assertEqual(
            six.ensure_binary(test_nonce, 'utf-8'),
            SignatureV4Authenticator.extract_nonce(six.ensure_binary('nonce=' + test_nonce, 'utf-8'))
        )

    def test_nonce_extraction_failure(self):
        with self.assertRaises(ValueError):
            SignatureV4Authenticator.extract_nonce(six.ensure_binary('nonce=too_short', 'utf-8'))


if __name__ == '__main__':
    unittest.main()
