import asyncio
from datetime import (
    datetime,
    timedelta,
)
import re
import unittest

from freezegun import (
    freeze_time,
)
import mohawk


from hawkserver import (
    authenticate_hawk_header,
)


def async_test(func):
    def wrapper(*args, **kwargs):
        future = func(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(future)
    return wrapper


class TestIntegration(unittest.TestCase):

    @async_test
    async def test_bad_id_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('not-id', 'my-secret', url, 'GET', 'my-type', b'my-content')

        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Unidentified id')
        self.assertEqual(creds, None)

    @async_test
    async def test_bad_secret_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'not-secret', url, 'GET', 'my-type', b'my-content')

        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Invalid mac')
        self.assertEqual(creds, None)

    @async_test
    async def test_bad_method_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'GET', 'my-type', b'my-content')

        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Invalid mac')
        self.assertEqual(creds, None)

    @async_test
    async def test_bad_content_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'my-type', b'not-content')

        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Invalid hash')
        self.assertEqual(creds, None)

    @async_test
    async def test_bad_content_type_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'not-type', b'my-content')

        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Invalid hash')
        self.assertEqual(creds, None)

    @async_test
    async def test_time_skew_then_not_authenticated(self):
        url = 'http://127.0.0.1:8080/v1/'
        past = datetime.now() + timedelta(seconds=-61)
        with freeze_time(past):
            header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'my-type', b'my-content')

        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Stale ts')
        self.assertEqual(creds, None)

    @async_test
    async def test_seen_nonce_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header(
            'my-other-id', 'my-other-secret', url, 'POST', 'my-type', b'my-content')

        passed_nonce = None
        passed_id = None

        async def seen_nonce_true(nonce, _id):
            nonlocal passed_nonce
            nonlocal passed_id
            passed_nonce = nonce
            passed_id = _id
            return True

        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce_true, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Invalid nonce')
        self.assertEqual(creds, None)
        self.assertEqual(passed_id, 'my-other-id')
        self.assertEqual(passed_nonce, dict(re.findall(r'([a-z]+)="([^"]+)"', header))['nonce'])

    @async_test
    async def test_invalid_header_format_then_not_authenticated(self):
        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            'Hawk d', 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Invalid header')
        self.assertEqual(creds, None)

    @async_test
    async def test_invalid_ts_format_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'not-type', b'my-content')

        bad_auth_header = re.sub(r'ts="[^"]+"', 'ts="non-numeric"', header)
        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            bad_auth_header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Invalid ts')
        self.assertEqual(creds, None)

    @async_test
    async def test_missing_nonce_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'not-type', b'my-content')

        bad_auth_header = re.sub(r', nonce="[^"]+"', '', header)
        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            bad_auth_header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, False)
        self.assertEqual(error, 'Missing nonce')
        self.assertEqual(creds, None)

    @async_test
    async def test_correct_header_then_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'my-type', b'my-content')

        is_auth, error, creds = await authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(is_auth, True)
        self.assertEqual(error, '')
        self.assertEqual(creds, {
            'id': 'my-id',
            'key': 'my-secret',
        })


def hawk_auth_header(key_id, secret_key, url, method, content_type, content):
    return mohawk.Sender({
        'id': key_id,
        'key': secret_key,
        'algorithm': 'sha256',
    }, url, method, content_type=content_type, content=content).request_header


async def seen_nonce(_, __):
    return False


async def lookup_credentials(_id):
    return \
        {'id': 'my-id', 'key': 'my-secret'} if _id == 'my-id' else \
        {'id': 'my-other-id', 'key': 'my-other-secret'} if _id == 'my-other-id' else \
        None
