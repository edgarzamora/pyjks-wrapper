=============
PyJKS Wrapper
=============

Indices and tables
------------------

* :ref:`genindex`
* :ref:`API Docs <modindex>`
* :ref:`search`

PyJKS Wrapper Library

Contents
--------

.. toctree::
    :glob:
    :maxdepth: 2

    overview

Technology stack
----------------

* Python 2.6+ or Python 3.3+
* Python Library for JKS/JCEKS: https://pypi.org/project/pyjks/#description

Installation
------------

The library provides a setup.py in order to be able to install it using
different distributions. We recommend install it using `pip` as it will
install all the requirements to use the library in a production environment.

.. code-block:: bash

    pip install << code-directory >>

Code Structure
--------------

Project code is held in a mono-repo, using a fairly standard tree structure:

.. code-block:: bash

   .
   ├── docs
   ├── pyjks_wrapper
   ├── requirements
   └── tests

(Other top-level directories such as ``/bin`` will be created by virtualenv and
are not shown here).

