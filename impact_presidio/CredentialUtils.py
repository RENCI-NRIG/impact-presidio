import OpenSSL.crypto as crypto
import hashlib
import base64
import pem
import ssl
import urllib.parse
import uuid

from flask import request, abort, make_response
from datetime import datetime
from jwcrypto import jwk
from requests import get
from ns_jwt import NSJWT
from json import dumps as json_dumps
from timeit import default_timer as timer

from impact_presidio.Logging import LOG, METRICS_LOG

_CAStore = crypto.X509Store()
_use_unverified_jwt = False


def _BAD_IDEA_set_use_unverified_jwt():
    global _use_unverified_jwt
    LOG.warning('BAD IDEA: Use of unverified JWTs requested!')
    LOG.warning('BAD IDEA: This option is for debugging ONLY!')
    LOG.warning('BAD IDEA: Please, please don\'t use this in production!')
    LOG.warning('BAD IDEA: You have been warned...')
    _use_unverified_jwt = True


def initialize_CA_store(CAFile=None):
    # Using this, with *full* knowledge that there's a potential
    # security issue.
    #
    # See: https://github.com/pyca/pyopenssl/pull/473
    if CAFile:
        root_certs = pem.parse_file(CAFile)
        if root_certs:
            for root_cert in root_certs:
                loaded_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                                                      root_cert.as_bytes())
                _CAStore.add_cert(loaded_cert)


def generate_safe_principal_id(key):
    sha256Hasher = hashlib.sha256()
    sha256Hasher.update(crypto.dump_publickey(crypto.FILETYPE_ASN1, key))
    return base64.urlsafe_b64encode(sha256Hasher.digest())


def generate_presidio_principal(keyFile):
    private_key = None
    with open(keyFile, 'rb') as kf:
        key_bytes = kf.read()
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_bytes)
    return generate_safe_principal_id(private_key)


def process_credentials():
    request.uuid = uuid.uuid4()
    request.start_time = timer()

    url_encoded_cert = request.headers.get('X-SSL-Cert')
    if url_encoded_cert:
        request.cert = urllib.parse.unquote(url_encoded_cert)
    else:
        return abort(401, (f'Your browser did not provide a client '
                           f'certificate. A client certificate is required '
                           f'by Presidio, so that you can be securely '
                           f'identified. Please contact your administrator '
                           f'if you require assistance in obtaining client '
                           f'certificate or installing one into your '
                           f'browser.'))

    cert_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, request.cert)
    x509_context = crypto.X509StoreContext(_CAStore, cert_x509)
    try:
        verify_result = x509_context.verify_certificate()
    except crypto.X509StoreContextError:
        return abort(401, (f'The client certificate your browser provided '
                           f'failed to verify against the set of Certificate '
                           f'Authorities recognized by this instance of '
                           f'Presidio. Please contact your administrator for '
                           f'assistance.'))

    # verify_result should be None, if the cert validated.
    if verify_result is not None:
        return abort(401, (f'The client certificate your browser provided '
                           f'failed to verify against the set of Certificate '
                           f'Authorities recognized by this instance of '
                           f'Presidio. Please contact your administrator for '
                           f'assistance.'))

    x509_DN_str = ''
    for k, v in cert_x509.get_subject().get_components():
        x509_DN_str = (f'{x509_DN_str}/{k.decode()}={v.decode()}')

    jwt_claims = None
    jwt_error = None
    if (len(request.args) > 0):
        jwt_field = request.args.get('ImPACT-JWT')
        if jwt_field:
            jwt_expiration = None
            (jwt_claims, jwt_error) = process_ns_jwt(jwt_field, x509_DN_str)
            if jwt_claims:
                jwt_expiration = jwt_claims.get('exp')
            else:
                return abort(401, jwt_error)

            if jwt_expiration is None:
                return abort(401, 'Unable to find expiration in JWT claims.')

            res = make_response('')
            res.set_cookie('ImPACT-JWT', value=jwt_field,
                           expires=jwt_expiration)
            res.headers['Location'] = request.base_url
            return res, 302

    # If we've gotten here, the JWT is now a cookie.
    # We'll grab that and process it.
    jwt_cookie = request.cookies.get('ImPACT-JWT')
    if jwt_cookie:
        (jwt_claims, jwt_error) = process_ns_jwt(jwt_cookie, x509_DN_str)
    else:
        return abort(401, (f'Cookie containing requisite information from '
                           f'Notary Service missing or expired. Please '
                           f'log into your Notary Service, and return '
                           f'to this site via the link it provides.'))

    if jwt_claims:
        request.verified_jwt_claims = jwt_claims
        cred_end = timer()
        cred_message = (
            f'Credential processing for request {request.uuid} '
            f'completed in {cred_end - request.start_time} seconds'
        )
        METRICS_LOG.info(cred_message)
    else:
        return abort(401, jwt_error)


def process_ns_jwt(jwt, DN_from_cert):
    ns_jwt = NSJWT()
    ns_jwt.setToken(jwt)

    # First, decode without verification, to get issuer.
    try:
        ns_jwt.decode(publicKey=None, verify=False)
    except Exception:
        return (None, 'Notary Service JWT failed unverified decode.')

    unverified_claims = None
    try:
        unverified_claims = ns_jwt.getClaims()
    except Exception:
        return (None, 'Failed to extract unverified claims from JWT.')

    verified_claims = None
    if not _use_unverified_jwt:
        ns_fqdn = unverified_claims.get('iss')
        ns_jwks_resp = None
        if ns_fqdn:
            ns_jwks_url = f'https://{ns_fqdn}/jwks'
            try:
                ns_jwks_resp = get(ns_jwks_url, verify=True)
            except Exception:
                nw_jwks_resp.close()
                return (None, 'GET of JWKS from Notary Service failed.')
        else:
            return (None, 'Unable to find issuer in JWT claims.')

        ns_jwks_status_code = None
        ns_jwks_keys_json = None
        if ns_jwks_resp:
            ns_jwks_status_code = ns_jwks_resp.status_code
            try:
                ns_jwks_keys_json = ns_jwks_resp.json()
            except Exception as e:
                return (None, 'Invalid JWKS response from Notary Service.')
            finally:
                ns_jwks_resp.close()

        if ns_jwks_status_code != 200:
            return (None, 'GET of JWKS from Notary Service reported an error.')

        ns_jwks_keys = None
        if ns_jwks_keys_json:
            ns_jwks_keys = ns_jwks_keys_json.get('keys')
        else:
            return (None, 'Empty JWKS returned by Notary Service.')

        ns_pubkey = None
        if ns_jwks_keys:
            num_keys = 0
            try:
                num_keys = len(ns_jwks_keys)
            except Exception:
                return (None, 'Could not determine number of keys in JWKS.')

            if not (num_keys > 0):
                return (None, 'Invalid number of keys in JWKS.')

            # Only grab the first key entry from the JWKS, then try to process.
            ns_jwk = ns_jwks_keys[0]
            try:
                ns_jwk_json = json_dumps(ns_jwk).encode('utf-8')
                ns_pubkey = jwk.JWK.from_json(ns_jwk_json)
            except Exception:
                return (None, 'Key entry could not be extracted from JWKS.')
        else:
            return (None, 'JWKS from Notary Service missing key container.')

        if ns_pubkey:
            try:
                ns_pubkey_pem = ns_pubkey.export_to_pem().decode('utf-8')
                ns_jwt.decode(publicKey=ns_pubkey_pem)
            except Exception:
                return (None, 'Notary Service JWT failed verified decode.')
        else:
            return (None, 'No valid public key provided by JWT issuer.')

        try:
            verified_claims = ns_jwt.getClaims()
        except Exception:
            return (None, 'Failed to extract verified claims from JWT.')

        computed_ns_token = generate_safe_principal_id(ns_pubkey)
        ns_token = verified_claims.get('ns-token')
        if ns_token:
            if ns_token != computed_ns_token.decode('utf-8'):
                return (None, (f'JWT ns-token does not match token '
                               f'computed from public key.'))
        else:
            return (None, 'Unable to find ns-token in JWT claims.')

    else:
        LOG.warning('BAD IDEA: Using unverified JWT claims, against advice...')
        verified_claims = unverified_claims

    expiry = verified_claims.get('exp')
    if expiry:
        dte = datetime.fromtimestamp(expiry)
        if datetime.now() > dte:
            return (None, 'JWT has expired.')
    else:
        return (None, 'Unable to find expiry in JWT claims.')

    userDN = verified_claims.get('sub')
    if userDN:
        if userDN != DN_from_cert:
            return (None, (f'JWT subject does not match '
                           f'value from client certificate.'))
    else:
        return (None, 'Unable to find subject in JWT claims.')

    return (verified_claims, None)
