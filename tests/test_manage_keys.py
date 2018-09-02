"""Tests for pyjks_wrapper.manage_keys."""

import base64
import hashlib
import os
import tempfile
from random import choice
from string import ascii_lowercase

import jks
from mock import MagicMock
from pymlconf import ConfigDict
from testtools import ExpectedException, TestCase
from testtools.matchers import (
    Equals,
    IsInstance,
)

from pyjks_wrapper import manage_keys
from pyjks_wrapper.manage_keys import AliasDoesNotExist


def make_string(prefix=None, length=10, chars=None):
    """Create a string of ascii characters of length `length` and return it.

    :param prefix: Optional prefix. If provided, the returned string
        will be of the form `<prefix>-<string>`, and length will be
        len(string) + len(prefix) + 1.
    :param length: The length for the new string.
    :param chars: The character set for the new string, as a string.
        Defaults to string.ascii_lowercase.
    :return string:

    """
    if not chars:
        chars = ascii_lowercase

    the_string = "".join(choice(chars) for _ in range(length))
    if prefix is not None:
        the_string = "{}-{}".format(prefix, the_string)

    return the_string


def make_mock_private_key():
    """Create and return a mock private key."""
    key_object = MagicMock(jks.PrivateKeyEntry)
    key_object._algorithm_oid = jks.DSA_OID
    key_object.pkey_pkcs8 = make_string(255).encode()
    key_object.pkey = make_string(255).encode()
    key_object.cert_chain = [
        ("X.509", make_string(2048).encode()),
    ]

    return key_object


class PyjksWrapperTestCase(TestCase):
    """Keystore-specific test case."""

    def patch(self, obj, attribute, value=None):
        """Monkey-patch 'obj.attribute' to 'value' while the test is running.

        If 'obj' has no attribute, then the monkey-patch will still go ahead,
        and the attribute will be deleted instead of restored to its original
        value.

        :param obj: The object to patch. Can be anything.
        :param attribute: The attribute on 'obj' to patch.
        :param value: The value to set 'obj.attribute' to. If None, a
            MagicMock() will be used by default.
        :return: the mocked attribute on `obj`.
        """
        if value is None:
            value = MagicMock()
        super().patch(obj, attribute, value)
        return value

    def patch_config(self, config):
        """Patch the get_config() function to return arbitrary values."""
        self.patch(manage_keys, "get_config").return_value = ConfigDict({
            "jks": ConfigDict(config),
        })


class LoadKeystoreTestCase(PyjksWrapperTestCase):
    """Check the library methods to load the keystore."""

    def setUp(self):
        """Create a keystore on disk, ready for testing."""
        super().setUp()
        path, password = self.make_keystore()
        self.keystore_path = path
        self.keystore_pass = password

        # Write the keystore password to a temp file too so that it can
        # be used in tests which rely on the password file being in a
        # configured location.
        _, file_name = tempfile.mkstemp(suffix="test_password")
        with open(file_name, "w") as password_file:
            password_file.write(self.keystore_pass)

        self.keystore_pass_file = file_name

    def tearDown(self):
        """Remove the temporary keystore and password file from disk."""
        os.remove(self.keystore_path)
        os.remove(self.keystore_pass_file)
        super().tearDown()

    def make_keystore(self):
        """Create an empty JKS keystore at a temporary location.

        :return: A tuple of:
            - The keystore's path,
            - The master password for the keystore,
        """
        _, file_name = tempfile.mkstemp(suffix="test_keystore")
        store_password = make_string()

        keystore = jks.KeyStore.new(store_type="jks", store_entries=[])
        keystore.save(file_name, store_password)

        return file_name, store_password

    def test_get_keystore_path(self):
        # get_keystore_path() returns the path to the Keystore file
        # as specified in configuration.
        the_path = os.path.join(*[
            make_string() for _ in range(3)
        ])
        self.patch_config({
            "keystore_path": the_path,
        })
        self.assertThat(manage_keys.get_keystore_path(), Equals(the_path))

    def test_get_keystore_password(self):
        # _get_keystore_password() returns the master password for the
        # keystore, as found in the configuration file.
        self.patch_config({
            "password_file_path": self.keystore_pass_file,
        })
        keystore_pass = manage_keys._get_keystore_password()
        self.assertThat(keystore_pass, Equals(self.keystore_pass))

    def test_load_keystore(self):
        # load_keystore() returns a jks KeyStore object loaded from the
        # the file specified in the keystore config.
        self.patch_config({
            "keystore_path": self.keystore_path,
            "password_file_path": self.keystore_pass_file,
        })
        keystore = manage_keys.load_keystore()
        self.assertThat(keystore, IsInstance(jks.KeyStore))

    def test_load_keystore_accepts_keystore_file_path_as_argument(self):
        # load_keystore() accepts an optional path argument from which
        # to load the keystore.
        self.patch(manage_keys, "_get_keystore_password").return_value = (
            self.keystore_pass)
        keystore = manage_keys.load_keystore(self.keystore_path)
        self.assertThat(keystore, IsInstance(jks.KeyStore))

    def test_load_keystore_provide_wrong_keystore_path(self):
        # Test the load keystore method when we provide via parameter the
        # keystore path instead of take it from the config file. This is
        # sending a wrong keystore path.
        self.assertRaises(
            FileNotFoundError,
            manage_keys.load_keystore,
            "./non-existing-keystore"
        )


class GetEncAliasKeystoreTestCase(PyjksWrapperTestCase):
    """Test alias management."""

    def test_get_alias_encrypted(self):
        # get_enc_alias(), when passed an unencrypted alias, will return
        # an encrypted, salted version of that alias which can be used
        # to access a secret key in the keystore.
        alias = make_string()
        salt_alias, salt = [make_string() for _ in range(2)]
        self.patch_config({
            "salt_alias": salt_alias,
        })

        keystore = self.patch(manage_keys, "get_keystore").return_value
        keystore.secret_keys = {
            salt_alias: MagicMock(key=salt.encode()),
        }

        expected_alias = hashlib.sha256((salt + alias).encode()).hexdigest()
        returned_alias = manage_keys.get_enc_alias(keystore, raw_alias=alias)
        self.assertThat(returned_alias, Equals(expected_alias))


class GetSecretTestCase(PyjksWrapperTestCase):
    """Tests for manage_keys.get_secret()."""

    def test_get_secret_returns_secret_at_alias(self):
        # get_secret() returns the secret stored in a keystore against a
        # given alias.
        alias, secret = make_string(), make_string()

        keystore = self.patch(manage_keys, "load_keystore").return_value
        keystore.secret_keys = {
            alias: MagicMock(key=secret.encode()),
        }

        returned_secret = manage_keys.get_secret(keystore, alias)
        self.assertThat(returned_secret, Equals(secret.encode()))

    def test_get_secret_raises_error_when_alias_doesnt_exist(self):
        # If get_secret() is asked to return the secret for an alias
        # which doesn't exist, it will raise an AliasDoesNotExist
        # exception.
        keystore = self.patch(manage_keys, "load_keystore").return_value
        keystore.secret_keys = {}

        wrong_alias = make_string()
        error_message = "No such alias {}.".format(wrong_alias)
        with ExpectedException(AliasDoesNotExist, error_message):
            manage_keys.get_secret(keystore, wrong_alias)


class GetPrivateKeyTestCase(PyjksWrapperTestCase):
    """Tests for manage_keys.get_private_key()."""

    def test_get_private_key_returns_key_at_alias(self):
        # get_private_key() returns the private key stored at a given
        # alias in the keystore.
        keystore = self.patch(manage_keys, "get_keystore").return_value
        alias = make_string()
        key_object = make_mock_private_key()
        expected_certs = [(
            "X.509",
            base64.b64encode(key_object.cert_chain[0][1]).decode("ascii")
        )]

        keystore.private_keys = {alias: key_object}
        private_key, certs = manage_keys.get_private_key(keystore, alias)

        self.expectThat(
            private_key,
            Equals(base64.b64encode(key_object.pkey_pkcs8).decode("ascii")),
        )
        self.expectThat(certs, Equals(expected_certs))

    def test_get_private_key_uses_pkey_value_for_rsa_keys(self):
        # get_private_key() returns the base64 encode pkey value from an
        # RSA-encrypted private key.
        keystore = self.patch(manage_keys, "get_keystore").return_value
        keystore._algorithm_oid = jks.RSA_ENCRYPTION_OID

        alias = make_string()
        key_object = make_mock_private_key()
        expected_certs = [(
            "X.509",
            base64.b64encode(key_object.cert_chain[0][1]).decode("ascii")
        )]

        keystore.private_keys = {alias: key_object}
        private_key, certs = manage_keys.get_private_key(keystore, alias)

        self.expectThat(
            private_key,
            Equals(base64.b64encode(key_object.pkey_pkcs8).decode("ascii")),
        )
        self.expectThat(certs, Equals(expected_certs))

    def test_get_private_key_raises_error_when_alias_doesnt_exist(self):
        # If get_private_key() is asked to return the private key for an
        # alias which doesn't exist, it will raise an AliasDoesNotExist
        # exception.
        keystore = self.patch(manage_keys, "get_keystore").return_value
        keystore.private_keys = {}

        wrong_alias = make_string()
        error_message = "No such alias {}.".format(wrong_alias)
        with ExpectedException(AliasDoesNotExist, error_message):
            manage_keys.get_private_key(keystore, wrong_alias)


class GetCertificateTestCase(PyjksWrapperTestCase):
    """Tests for manage_keys.get_certificate()."""

    def test_get_certificate_accepts_alias(self):
        # get_certificate() returns a tuple of cert_type, cert_value for
        # a given certificate in the keystore.
        alias = make_string()
        keystore = self.patch(manage_keys, "get_keystore").return_value
        keystore.certs = {
            alias: MagicMock(
                cert=make_string().encode(),
                type=make_string(),
            ),
        }

        cert_type, cert_value = manage_keys.get_certificate(
            keystore, alias
        )
        expected_value = base64.b64encode(
            keystore.certs[alias].cert).decode("ascii")

        self.expectThat(cert_type, Equals(keystore.certs[alias].type))
        self.expectThat(cert_value, Equals(expected_value))

    def test_get_certificate_raises_error_when_alias_doesnt_exist(self):
        # If get_certificate() is asked to return the certificate for an
        # alias which doesn't exist, it will raise an AliasDoesNotExist
        # exception.
        keystore = self.patch(manage_keys, "get_keystore").return_value
        keystore.certs = {}

        wrong_alias = make_string()
        error_message = "No such alias {}.".format(wrong_alias)
        with ExpectedException(AliasDoesNotExist, error_message):
            manage_keys.get_certificate(keystore, wrong_alias)
