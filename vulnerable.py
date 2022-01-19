import os
import rsa
import time
import uuid

from flask import Flask, request

from jwt import JsonWebToken

app = Flask(__name__)

if not os.path.isfile('hs256.key'):
    with open('hs256.key', 'w') as f:
        f.write(uuid.uuid4().hex)

with open('hs256.key', 'r') as f:
    HS256_KEY = f.read()

if not os.path.isfile('rs256_public.key'):
    (public_key, private_key) = rsa.newkeys(512)

    with open('rs256_public.key', 'wb') as f:
        f.write(public_key.save_pkcs1("PEM"))

    with open('rs256_private.key', 'wb') as f:
        f.write(private_key.save_pkcs1("PEM"))

with open('rs256_public.key', 'rb') as f:
    RS256_KEY_PUBLIC = f.read()

with open('rs256_private.key', 'rb') as f:
    RS256_KEY_PRIVATE = f.read()

RS256_KEY_PUBLIC_OBJ = rsa.PublicKey.load_pkcs1(RS256_KEY_PUBLIC, "PEM")
RS256_KEY_PRIVATE_OBJ = rsa.PrivateKey.load_pkcs1(RS256_KEY_PRIVATE, "PEM")

@app.route("/")
def hello_world():
    return "<h1>Vulnerable endpoints:</h1><ul>"+(''.join([
        f'<li><a href="{route}">{route}</a></li>'
        for route in [
            '/signature_not_verified',
            '/alg_none_allowed',
            '/alg_confusion',
            '/not_vulnerable'
        ]]))

@app.route("/signature_not_verified")
def signature_not_verified():
    if 'Authorization' not in request.headers:
        valid_authorization = JsonWebToken.build({'alg': 'HS256'},{'username': 'guest'}, key=HS256_KEY)
        return f"<p>A valid authorization header is: <code>{valid_authorization.to_token()}</code>. Now assume the username admin.</p>"
    else:
        jwt = JsonWebToken(request.headers['Authorization'])

        assert jwt.header['alg'] == 'HS256'
        assert 'username' in jwt.payload

        if jwt.payload['username'] == 'admin':
            return f"<p>Success! Your username is admin.</p>"
        else:
            return f"<p>Not quite. Your username needs to be admin.</p>"

@app.route("/alg_none_allowed")
def alg_none_allowed():
    if 'Authorization' not in request.headers:
        valid_authorization = JsonWebToken.build({'alg': 'HS256'},{'username': 'guest'}, key=HS256_KEY)
        return f"<p>A valid authorization header is: <code>{valid_authorization.to_token()}</code>. Now assume the username admin.</p>"
    else:
        jwt = JsonWebToken(request.headers['Authorization'])

        assert jwt.header['alg'] in ['None', 'HS256']
        assert 'username' in jwt.payload

        jwt.key = HS256_KEY
        if not jwt.verify():
            print(jwt)
            return ("<p>Failed verification. Use alg None to solve this.</p>", 400)

        if jwt.payload['username'] == 'admin':
            return f"<p>Success! Your username is admin.</p>"
        else:
            return f"<p>Not quite. Your username needs to be admin.</p>"

@app.route("/alg_confusion_public_key")
def alg_confusion_public_key():
    return RS256_KEY_PUBLIC

@app.route("/alg_confusion")
def alg_confusion():
    if 'Authorization' not in request.headers:
        valid_authorization = JsonWebToken.build({'alg': 'RS256'},{'username': 'guest', 'iat': int(time.time())}, key=(RS256_KEY_PUBLIC_OBJ, RS256_KEY_PRIVATE_OBJ))
        return f'<p>A valid authorization header is: <code>{valid_authorization.to_token()}</code>. Now assume the username admin.</p><p>You have two approaches for obtaining the public key:<ol><li>Download the public key here: <a href="/alg_confusion_public_key">/alg_confusion_public_key</a>.</li><li>Derive the public key using <a href="https://github.com/silentsignal/rsa_sign2n/tree/release/standalone">https://github.com/silentsignal/rsa_sign2n/tree/release/standalone</a>.</li></ol></p>'
    else:
        jwt = JsonWebToken(request.headers['Authorization'])

        assert jwt.header['alg'] in ['RS256', 'HS256']
        assert 'username' in jwt.payload

        if jwt.header['alg'] == 'RS256':
            jwt.key = RS256_KEY_PUBLIC_OBJ
        else:
            jwt.key = RS256_KEY_PUBLIC

        if not jwt.verify():
            return ("<p>Failed verification. Use alg None to solve this.</p>", 400)

        if jwt.payload['username'] == 'admin':
            return f"<p>Success! Your username is admin.</p>"
        else:
            return f"<p>Not quite. Your username needs to be admin.</p>"

@app.route('/not_vulnerable')
def not_vulnerable():
    if 'Authorization' not in request.headers:
        valid_authorization = JsonWebToken.build({'alg': 'HS256'},{'username': 'guest'}, key=HS256_KEY)
        return f"<p>A valid authorization header is: <code>{valid_authorization.to_token()}</code>. You need the key to assume admin. It is {HS256_KEY}.</p>"
    else:
        jwt = JsonWebToken(request.headers['Authorization'])

        assert jwt.header['alg'] == 'HS256'
        assert 'username' in jwt.payload

        jwt.key = HS256_KEY
        if not jwt.verify():
            print(jwt)
            return ("<p>Failed verification. You need to use the provided key.</p>", 400)

        if jwt.payload['username'] == 'admin':
            return f"<p>Success! Your username is admin.</p>"
        else:
            return f"<p>Not quite. Your username needs to be admin.</p>"

if __name__ == '__main__':
    app.run(debug=True)