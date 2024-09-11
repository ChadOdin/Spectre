import yaml
import random
import urllib.parse

# loading our payloads from payloads.yaml
def get_payload(vuln_type, payload_type='basic', custom_payload=None):
    if custom_payload:
        return custom_payload
    
    try:
        with open(f'payloads/{vuln_type}.yaml', 'r') as file:
            payloads = yaml.safe_load(file)
            return random.choice(payloads.get(payload_type, []))
    except FileNotFoundError:
        logging.error(f"Payload file for {vuln_type} not found!")
        return None

# mutating our payloads by encoding them or altering them
def mutate_payload(payload):
    mutations = []

    # URL encoding
    mutations.append(urllib.parse.quote(payload))

    # Hex encoding
    mutations.append(payload.encode('utf-8').hex())

    # Base64 encoding
    import base64
    mutations.append(base64.b64encode(payload.encode()).decode('utf-8'))

    # reverse payload for obfuscation
    mutations.append(payload[::-1])

    # HTML entity encoding
    mutations.append(payload.replace('<', '&lt;').replace('>', '&gt;'))

    # uppercase mutation \ useful for bypassing WAF
    mutations.append(payload.upper())

    # lowercase mutation \ useful for bypassing WAF
    mutations.append(payload.lower())

    return mutations

# encoding payloads as needed
def encode_payload(payload, encoding_type):
    if encoding_type == 'url':
        return urllib.parse.quote(payload)
    elif encoding_type == 'hex':
        return payload.encode('utf-8').hex()
    elif encoding_type == 'base64':
        import base64
        return base64.b64encode(payload.encode()).decode('utf-8')
    else:
        return payload
