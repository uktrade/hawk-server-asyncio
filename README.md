# hawk-server-asyncio [![CircleCI](https://circleci.com/gh/uktrade/hawk-server-asyncio.svg?style=svg)](https://circleci.com/gh/uktrade/hawk-server-asyncio) [![Test Coverage](https://api.codeclimate.com/v1/badges/b03db2f3cb9fedeb4ea7/test_coverage)](https://codeclimate.com/github/uktrade/hawk-server-asyncio/test_coverage)

Utility function to perform the server-side of Hawk authentication


## Installation

```bash
pip install hawk-server-asyncio
```


## Usage

```python
from hawkserver import authenticate_hawk_header

async def lookup_credentials(id):
    # Return {'id': 'some-id', 'key': 'some-secret'} matching credentials,
    # or None if credentials can't be found

async def seen_nonce(nonce, id):
    # Store nonce, return True if nonce previously seen

is_authenticated, error_message, credentials = await authenticate_hawk_header(
    lookup_credentials, seen_nonce, max_skew,
    header, method, host, port, path, content_type, content,
)
if not is_authenticated:
    # Return error or raise exception as needed
```
