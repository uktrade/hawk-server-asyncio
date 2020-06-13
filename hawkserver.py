from base64 import (
    b64encode,
)
from datetime import (
    datetime,
)
import hashlib
import hmac
import re


async def authenticate_hawk_header(
        lookup_credentials, seen_nonce, max_skew,
        header, method, host, port, path, content_type, content,
):
    is_valid_header = re.match(r'^Hawk (((?<="), )?[a-z]+="[^"]*")*$', header)
    if not is_valid_header:
        return 'Invalid header', None

    parsed_header = dict(re.findall(r'([a-z]+)="([^"]+)"', header))

    required_fields = ['ts', 'hash', 'mac', 'nonce', 'id']
    missing_fields = [
        field for field in required_fields
        if field not in parsed_header
    ]
    if missing_fields:
        return f'Missing {missing_fields[0]}', None

    if not re.match(r'^\d+$', parsed_header['ts']):
        return 'Invalid ts', None

    matching_credentials = await lookup_credentials(parsed_header['id'])
    if not matching_credentials:
        return 'Unidentified id', None

    canonical_payload = (
        f'hawk.1.payload\n{content_type}\n'.encode('ascii'),
        content, b'\n',
    )
    payload_hash = _base64_digest(canonical_payload)

    canonical_request = \
        f'hawk.1.header\n{parsed_header["ts"]}\n{parsed_header["nonce"]}' \
        f'\n{method}\n{path}\n{host}\n{port}\n' \
        f'{payload_hash}\n\n'
    correct_mac = _base64_mac(
        matching_credentials['key'].encode('ascii'), canonical_request.encode('ascii'))

    if not hmac.compare_digest(payload_hash, parsed_header['hash']):
        return 'Invalid hash', None

    if not abs(int(datetime.now().timestamp()) - int(parsed_header['ts'])) <= max_skew:
        return 'Stale ts', None

    if not hmac.compare_digest(correct_mac, parsed_header['mac']):
        return 'Invalid mac', None

    if await seen_nonce(parsed_header['nonce'], matching_credentials['id']):
        return 'Invalid nonce', None

    return None, matching_credentials


def _base64_digest(chunks):
    m = hashlib.sha256()
    for chunk in chunks:
        m.update(chunk)
    return b64encode(m.digest()).decode('ascii')


def _base64_mac(key, data):
    return b64encode(hmac.new(key, data, hashlib.sha256).digest()).decode('ascii')
