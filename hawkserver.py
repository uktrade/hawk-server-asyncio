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
        return False, 'Invalid header', None

    parsed_header = dict(re.findall(r'([a-z]+)="([^"]+)"', header))

    required_fields = ['ts', 'hash', 'mac', 'nonce', 'id']
    missing_fields = [
        field for field in required_fields
        if field not in parsed_header
    ]
    if missing_fields:
        return False, f'Missing {missing_fields[0]}', None

    if not re.match(r'^\d+$', parsed_header['ts']):
        return False, 'Invalid ts', None

    matching_credentials = await lookup_credentials(parsed_header['id'])
    if not matching_credentials:
        return False, 'Unidentified id', None

    canonical_payload = \
        b'hawk.1.payload' + b'\n' + \
        content_type.encode('utf-8') + b'\n' + \
        content + b'\n'
    payload_hash = _base64_digest(canonical_payload)

    canonical_request = \
        f'hawk.1.header\n{parsed_header["ts"]}\n{parsed_header["nonce"]}' \
        f'\n{method}\n{path}\n{host}\n{port}\n' \
        f'{payload_hash}\n\n'
    correct_mac = _base64_mac(
        matching_credentials['key'].encode('utf-8'), canonical_request.encode('utf-8'))

    if not hmac.compare_digest(payload_hash, parsed_header['hash']):
        return False, 'Invalid hash', None

    if not abs(int(datetime.now().timestamp()) - int(parsed_header['ts'])) <= max_skew:
        return False, 'Stale ts', None

    if not hmac.compare_digest(correct_mac, parsed_header['mac']):
        return False, 'Invalid mac', None

    if await seen_nonce(parsed_header['nonce'], matching_credentials['id']):
        return False, 'Invalid nonce', None

    return True, '', matching_credentials


def _base64_digest(data):
    return b64encode(hashlib.sha256(data).digest()).decode('utf-8')


def _base64_mac(key, data):
    return b64encode(hmac.new(key, data, hashlib.sha256).digest()).decode('utf-8')
