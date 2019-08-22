# hawk-server-asyncio

Utility function to perform the server-side of Hawk authentication

> Work-in-progress. This README serves as a rough design spec


## Installation

```bash
pip install hawkserver
```


## Usage

```python
from hawkserver import authenticate_hawk_header

async def lookup_credentials(id):
    # Return credentials matching id, or None if credentials can't be found

async def seen_nonce(nonce):
    # Store nonce, return True if nonce previously seen

is_authenticated, error_message, credentials = authenticate_hawk_header(
    lookup_credentials, seen_nonce,
    header, method, host, port, path, content_type, content,
)
```
