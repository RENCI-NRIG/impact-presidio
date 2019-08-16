import OpenSSL.crypto as crypto
import hashlib
import base64
import pem
import ssl
import urllib.parse

from flask import request, abort, make_response
from ns_jwt import NSJWT
from datetime import datetime

from impact_presidio.Logging import LOG

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
    url_encoded_cert = request.headers.get('X-SSL-Cert')
    if url_encoded_cert:
        request.cert = urllib.parse.unquote(url_encoded_cert)
    else:
        return abort(401, ("Your browser did not provide a client " +
                           "certificate. A client certificate is required " +
                           "by Presidio, so that you can be securely " +
                           "identified. Please contact your administrator " +
                           "if you require assistance in obtaining client " +
                           "certificate or installing one into your " +
                           "browser."))

    cert_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, request.cert)
    x509_context = crypto.X509StoreContext(_CAStore, cert_x509)
    try:
        verify_result = x509_context.verify_certificate()
    except crypto.X509StoreContextError:
        return abort(401, ("The client certificate your browser provided " +
                           "failed to verify against the set of Certificate " +
                           "Authorities recognized by this instance of " +
                           "Presidio. Please contact your administrator for " +
                           "assistance."))

    # verify_result should be None, if the cert validated.
    if verify_result is not None:
        return abort(401, ("The client certificate your browser provided " +
                           "failed to verify against the set of Certificate " +
                           "Authorities recognized by this instance of " +
                           "Presidio. Please contact your administrator for " +
                           "assistance."))

    x509_DN_str = ""
    for k, v in cert_x509.get_subject().get_components():
        x509_DN_str = (x509_DN_str +
                       "/" +
                       k.decode() +
                       "=" +
                       v.decode())

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
                return abort(401, "Unable to find expiration in JWT claims.")

            res = make_response("")
            res.set_cookie("ImPACT-JWT", value=jwt_field,
                           expires=jwt_expiration)
            res.headers['Location'] = request.base_url
            return res, 302

    # If we've gotten here, the JWT is now a cookie.
    # We'll grab that and process it.
    jwt_cookie = request.cookies.get('ImPACT-JWT')
    if jwt_cookie:
        (jwt_claims, jwt_error) = process_ns_jwt(jwt_cookie, x509_DN_str)
    else:
        return abort(401, ("Cookie containing requisite information from " +
                           "Notary Service missing or expired. Please " +
                           "log into your Notary Service, and return " +
                           "to this site via the link it provides."))

    if jwt_claims:
        request.verified_jwt_claims = jwt_claims
    else:
        return abort(401, jwt_error)


def process_ns_jwt(jwt, DN_from_cert):
    ns_jwt = NSJWT()
    ns_jwt.setToken(jwt)

    # First, decode without verification, to get issuer.
    try:
        ns_jwt.decode(publicKey=None)
    except:
        return (None, "Notary Service JWT failed unverified decode.")

    unverified_claims = None
    try:
        unverified_claims = ns_jwt.getClaims()
    except:
        return (None, "Failed to extract unverified claims from JWT.")

    verified_claims = None
    if not _use_unverified_jwt:
        ns_fqdn = unverified_claims.get('iss')
        ns_pubkey = None
        if ns_fqdn:
            try:
                ns_cert = ssl.get_server_certificate((ns_fqdn, 443))
                ns_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ns_cert)
                ns_pubkey = ns_x509.get_pubkey()
            except:
                return (None, ('Unable to get server certificate ' +
                               'from Notary Service.'))
        else:
            return (None, "Unable to find issuer in JWT claims.")

        if ns_pubkey:
            try:
                ns_pubkey_pem = crypto.dump_publickey(crypto.FILETYPE_PEM,
                                                      ns_pubkey)
                ns_jwt.decode(publicKey=ns_pubkey_pem)
            except:
                return (None, "Notary Service JWT failed verified decode.")
        else:
            return (None, "Could not obtain public key from JWT issuer.")

        try:
            verified_claims = ns_jwt.getClaims()
        except:
            return (None, "Failed to extract verified claims from JWT.")

        computed_ns_token = generate_safe_principal_id(ns_pubkey)
        ns_token = verified_claims.get('ns-token')
        if ns_token:
            if ns_token != computed_ns_token.decode('utf-8'):
                return (None, ("JWT ns-token does not match token " +
                               "computed from public key."))
        else:
            return (None, "Unable to find ns-token in JWT claims.")

    else:
        LOG.warning('BAD IDEA: Using unverified JWT claims, against advice...')
        verified_claims = unverified_claims

    expiry = verified_claims.get('exp')
    if expiry:
        dte = datetime.fromtimestamp(expiry)
        if datetime.now() > dte:
            return (None, "JWT has expired.")
    else:
        return (None, "Unable to find expiry in JWT claims.")

    userDN = verified_claims.get('sub')
    if userDN:
        if userDN != DN_from_cert:
            return (None, ("JWT subject does not match " +
                           "value from client certificate."))
    else:
        return (None, "Unable to find subject in JWT claims.")

    return (verified_claims, None)
