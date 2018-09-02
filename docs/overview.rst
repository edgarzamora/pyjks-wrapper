
Overview
========

This library works as a wrapper of the PyJKS library. It includes all
the code related to connect and retrieve information from the keystore.
It means our python applications (e.g Django or Flask app), will be able to
install/use this library. This library contains all needed tools to obtain
the correct keys decrypted.


Do we need to use JCEKS database?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The "Cannot store non-PrivateKeys" error message usually indicates you are
trying to use secret symmetric keys with a JKS keystore type.
The JKS keystore type only supports asymmetric (public/private)
keys. You would have to create a new JCEKS type keystore which support store
secrets.


How it will look like?
^^^^^^^^^^^^^^^^^^^^^^

A config file using the keystore will looks like that:

.. code-block:: none

   config.file =============================================
    "keystore_location": "path/to/keystore",
    "keystore_password": "path/to/keystore/password",

    "import_config": {
      "type": "rabbitmq",
      "username": "rmq_user",
      "password": "rmq_password",
      "host": "localhost",
      "exchange_name": "queue"
    }
   =========================================================


Notes
-----

* `keystore_password` will have the path to the file where the plain text
  password is stored, but it only must be visible for the user who can access
  to the keystore.
* Using a file to store the keystore_password allows us to make easier the
  password rotation, as we only will need to update this file, instead of all
  config files, and also give only read/write permissions to this file to the
  user who have permissions to manage the keys.
* `rmq_user` and `rmq` are not the real password or username.
  They are the alias to find the real password and username on the keystore.

Then in our application we can do something like that:

.. code-block:: python

   from pyjks_wrapper import manage_keys

   keystore = manage_keys.load_keystore()
   rmq_user = manage_keys.get_secret(keystore, config.import_config.username)


Also, it allows the possibility to use a salt. In case we use salt,
the keystore entries will looks a little bit different. Following the
example above, when we activate the `salt`:
keystore = manage_keys.load_keystore()
rmq_user = manage_keys.get_secret(keystore, config.import_config.username)

Keystore content (only visible when you have the key to access). It contains
three objects in this example. The `salt` used to generate the hash of the other
keys, the rabbit_mq username and the rabbit_mq password, but as you can see the
last two cannot be read easily as they has been hashed using the `salt` and a
specific hash function.

.. code-block:: none

   {
    u'salt': <jks.jks.SecretKeyEntry object at 0x7fdd2ee8ed10>,
    u'a9547a84aba16dfa0490ba6b5d52efc524b947b84ca2e05728027f92ec91420e': <jks.jks.SecretKeyEntry object at 0x7fdd2ee8ed90>,
    u'f48f69bf7ae1435ba9ada7ed5f2d3415067517462a91a2684afe7c4bb249c7a6': <jks.jks.SecretKeyEntry object at 0x7fdd2ee8e4d0>
   }


So, the `rmq_user` and `rmq_pass` alias has been hashed using the salt
in order to obtain a non-direct relationship between the real alias and the
hashed alias.

In this example I used the next salt:

.. code-block:: none

   # Raw SALT pass
   SALT=io8buehc;jkmjnwcelij\bda
