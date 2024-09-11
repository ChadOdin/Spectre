# utils/payload_encoder.py

import base64
import urllib.parse

def encode_payload(payload, encoding_type):
    if encoding_type == 'url':
        return urllib.parse.quote(payload)
    elif encoding_type == 'hex':
        return payload.encode('utf-8').hex()
    elif encoding_type == 'base64':
        return base64.b64encode(payload.encode()).decode('utf-8')
    else:
        return payload
