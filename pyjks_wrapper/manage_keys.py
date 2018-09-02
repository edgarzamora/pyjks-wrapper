"""Manage keys module."""
import base64
import hashlib

import jks

from .config import get_config


class AliasDoesNotExist(Exception):
    """Raised when an alias does not exist in the keystore."""


def _get_keystore_password():
    """Return the keystore password."""
    password_path = get_config().jks.password_file_path

    with open(password_path, "r") as f:
        password = f.read()

    return password.strip()


def _get_value_or_raise_error(collection, alias):
    """Return the value for `alias` from `collection`.

    :raises: AliasDoesNotExist if `alias` does not exist in `collection`.
    """
    value = collection.get(alias)
    if value is None:
        raise AliasDoesNotExist("No such alias {}.".format(alias))

    return value


def get_keystore_path():
    """Return the keystore path defined in the config files."""
    return get_config().jks.keystore_path


def load_keystore(keystore_path=None):
    """Load the keystore and return the keystore instance."""
    keystore_path = keystore_path if keystore_path else get_keystore_path()
    password = _get_keystore_password()
    return jks.KeyStore.load(keystore_path, password)


def get_enc_alias(keystore, raw_alias):
    """Return the encrypted alias."""
    salt_alias = get_config().jks.salt_alias
    salt = keystore.secret_keys.get(salt_alias)
    salt_alias_concat = salt.key.decode("utf-8") + raw_alias
    return hashlib.sha256(salt_alias_concat.encode("utf-8")).hexdigest()


def get_secret(keystore, alias):
    """Return the secret identified by the `alias` stored on the keystore."""
    if get_config().jks.use_salt:
        alias = get_enc_alias(keystore, alias)

    return _get_value_or_raise_error(keystore.secret_keys, alias).key


def get_certificate(keystore, alias):
    """Return the certificate identified by the `alias` from the keystore."""
    if get_config().jks.use_salt:
        alias = get_enc_alias(keystore, alias)

    certificate = _get_value_or_raise_error(keystore.certs, alias)

    cert_value = base64.b64encode(certificate.cert).decode("ascii")
    cert_type = certificate.type
    return cert_type, cert_value


def get_private_key(keystore, alias, key_pass=None):
    """Return the private key identified by the `alias` from the keystore.

    :return: A tuple with the private key and the certificates it can
        store/sign.
    """
    if get_config().jks.use_salt:
        alias = get_enc_alias(keystore, alias)

    private_key = _get_value_or_raise_error(keystore.private_keys, alias)

    private_key.decrypt(key_pass)

    if private_key._algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
        pk_value = private_key.pkey
    else:
        pk_value = private_key.pkey_pkcs8

    certs = [
        (cert[0], base64.b64encode(cert[1]).decode("ascii"))
        for cert in private_key.cert_chain
    ]

    return base64.b64encode(pk_value).decode("ascii"), certs
