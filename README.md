# PyJKS Wrapper

PyJKS Wrapper Library. This library wrapps the existing PyJKS library in order 
to make easier the integration of Keystore in your Python projects. It 
implements some simple methods to extract all kind of information that can be 
stored in a Java Keystore, allowing to integrate our projectcs with keystore 
with a less intrusive way.


Technology stack
----------------

* Python 2.6+ or Python 3.3+ 
* Python Library for JKS/JCEKS: https://pypi.org/project/pyjks/#description

Installation
------------

The library provides a setup.py in order to be able to install it using
different distributions. We recommend install it using `pip` as it will
install all the requirements to use the library in a production environment.

    pip install << code-directory >>

Code Structure
--------------

Project code is held in a mono-repo, using a fairly standard tree structure:

```
   .
   ├── docs
   ├── pyjks_wrapper
   ├── requirements
   └── tests
```

(Other top-level directories such as ``/bin`` will be created by virtualenv and
are not shown here).


Make file
---------
The library code contains a make file which offers some useful commands:

- `make venv` - Create a dev virtual environment.
- `make install-dependencies` - Install all required dependencies on the dev 
environment.
- `make lint`: Runs the code quality / linting tools across all applications.
- `make test` - Run all tests in the Docker container
- `make build-docs` - Generate docs in HTML using Sphinx

Configuration
-------------

To configure this library, we need to include a configuration file which 
will tell to this library the keystore location and more information. See 
the file `default_config.yaml` where you can see an example of the 
configuration needed for this application. 

The library will locate the configuration path based on environment variable. 
So, you need to define the environment variable KEYSTORE_CONF which will 
contain the path to the config file. It can be done doing the following:

```bash
export KEYSTORE_CONF=/path/to/your/config/file
```


#### How it will look like?

A config file using the keystore will looks like that:

```
config.file =============================================
 "keystore_location": "path/to/keystore",
 "keystore_password": "path/to/keystore/password",

 "import_config": {
   "type": "rabbitmq",
   "username": "rmq_user",
   "password": "rmq_pass",
   "host": "localhost",
   "exchange_name": "queue"
 }
=========================================================
```
Note:
- `keystore_password` will have the path to the file where the plain text
password is stored, but it only must be visible for the user who can access
to the keystore.

- Using a file to store the keystore_password allows us to make easier the
password rotation, as we only will need to update this file, instead of all
config files, and also give only read/write permissions to this file to the
user who have permissions to manage the keys.

- `rmq_user` and `rmq_pass` are not the real useername and password. They
are the alias to find the real password and username on the keystore.

Then in our application we can do something like that:

```python
from pyjks_wrapper import manage_keys

keystore = manage_keys.load_keystore()
rmq_user = manage_keys.get_secret(keystore, config.import_config.username)
```

Also, it allows the possibility to use a salt. In case we use salt, 
the keystore entries will looks a little bit different. Following the 
example above, when we activate the `salt`:

Keystore content (only visible when you have the key to access). It contains
three objects in this example. The `salt` used to generate the hash of the other
keys, the rabbit_mq username and the rabbit_mq password, but as you can see the
last two cannot be read easily as they has been hashed using the `salt` and a
specific hash function.

```
{
 u'salt': <jks.jks.SecretKeyEntry object at 0x7fdd2ee8ed10>,
 u'a9547a84aba16dfa0490ba6b5d52efc524b947b84ca2e05728027f92ec91420e': <jks.jks.SecretKeyEntry object at 0x7fdd2ee8ed90>,
 u'f48f69bf7ae1435ba9ada7ed5f2d3415067517462a91a2684afe7c4bb249c7a6': <jks.jks.SecretKeyEntry object at 0x7fdd2ee8e4d0>
}
```

So, the `rmq_user` and `rmq_pass` alias has been hashed using the salt
in order to obtain a non-direct relationship between the real alias and the
hashed alias.

In this example I used the next salt:
```
# Raw SALT pass
SALT=io8buehc;jkmjnwcelij\bda
```

TO DO List
----------

* Allow more configuration files formats (currently is using YAML)
* Allow to define the configuration file location in different ways. 
* 
