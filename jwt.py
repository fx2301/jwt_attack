import base64
import binascii
import hashlib
import hmac
import json
import rsa

class JsonWebToken:
    def __init__(self, token, key=None):
        self.token = token
        self.key = key

        parts = token.split('.')
        assert len(parts) == 3, f'Expected 3 parts to JWT. Got {len(parts)}'

        header_raw, payload_raw, self.signature = list(map(self.decode, parts))

        self.header = json.loads(header_raw)
        self.payload = json.loads(payload_raw)

    def decode(self, part):
        try:
            return base64.urlsafe_b64decode(part.encode('utf-8'))
        except binascii.Error:
            try:
                return base64.urlsafe_b64decode((part+'=').encode('utf-8'))
            except binascii.Error:
                return base64.urlsafe_b64decode((part+'==').encode('utf-8'))

    def encoded_header(self):
        # NOTE if the header is unchanged, we should not change the encoded output
        return JsonWebToken.encode(json.dumps(self.header).encode('utf-8'))

    def encoded_payload(self):
        # NOTE if the payload is unchanged, we should not change the encoded output
        return JsonWebToken.encode(json.dumps(self.payload).encode('utf-8'))

    def encoded_signature(self):
        key = self.key
        if isinstance(key, str):
            key = key.encode('utf-8')

        content = f'{self.encoded_header()}.{self.encoded_payload()}'.encode('utf-8')
        if key is not None and self.header['alg'] == 'HS256':
            return JsonWebToken.encode(hmac.new(key, content, hashlib.sha256).digest())
        elif key is not None and self.header['alg'] == 'RS256' and isinstance(key, tuple):
            # we can only sign with the public key
            _, private_key = key
            return JsonWebToken.encode(rsa.sign(content, private_key, 'SHA-256'))
        else:
            return JsonWebToken.encode(self.signature)

    def to_token(self):
        return f'{self.encoded_header()}.{self.encoded_payload()}.{self.encoded_signature()}'

    def build_with_alg_none(self):
        jwt = JsonWebToken(self.to_token(), key=self.key)
        jwt.header['alg'] = 'None'
        jwt.signature = bytes()
        jwt.key = None
        return jwt

    def build_with_alg_hsa(self):
        assert self.key is not None
        assert self.header['alg'] == 'RS256'
        jwt = JsonWebToken(self.to_token(), key=self.key)
        jwt.header['alg'] = 'HS256'
        return jwt

    def verify(self):
        assert self.header['alg'] in ['None', 'HS256', 'RS256'], "Expected supported algorithm"

        if self.header['alg'] == 'None':
            return len(self.signature) == 0
        elif self.header['alg'] == 'HS256':
            assert self.key is not None
            return self.encoded_signature() == JsonWebToken.encode(self.signature)
        elif self.header['alg'] == 'RS256':
            assert self.key is not None
            content = f'{self.encoded_header()}.{self.encoded_payload()}'.encode('utf-8')
            key = self.key
            if isinstance(key, tuple):
                key, _ = key
            return rsa.verify(content, self.signature, key)
            
    def __repr__(self):
        return json.dumps({
            'token': self.to_token(),
            'header': self.header,
            'payload': self.payload,
            'signature': self.encoded_signature()
        }, indent=2)

    def encode(part):
        return base64.urlsafe_b64encode(part).decode('utf-8').rstrip('=')

    def build(header, payload, key):
        return JsonWebToken(f'{JsonWebToken.encode(json.dumps(header).encode("utf-8"))}.{JsonWebToken.encode(json.dumps(payload).encode("utf-8"))}.', key=key)

