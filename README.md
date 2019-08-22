# hawk-server-asyncio

Utility function to perform the server-side of Hawk authentication


## Installation

```bash
pip install hawkserver
```


## Usage

```python
from hawkserver import authenticate_hawk_header

async def lookup_credentials(id):
    # Return {'id': 'some-id', 'key': 'some-secret'} matching credentials,
    # or None if credentials can't be found

async def seen_nonce(nonce):
    # Store nonce, return True if nonce previously seen

is_authenticated, error_message, credentials = await authenticate_hawk_header(
    lookup_credentials, seen_nonce,
    header, method, host, port, path, content_type, content,
)
if not is_authenticated:
    # Return error or raise exception as needed
```
