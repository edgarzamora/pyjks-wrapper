"""Configuration module for pyjks_wrapper."""

import os.path

from pymlconf import ConfigManager


def get_config():
    """Return the current application config object.

    :return: `ConfigManager`
    """
    path = os.environ.get("KEYSTORE_CONFIG", None)
    if path is None:
        raise ValueError(
            "No valid path found for configuration file. Either pass a path "
            "to set_config() or set the KEYSTORE_CONFIG environment variable.")
    path = os.path.abspath(os.path.expanduser(path))
    config = ConfigManager()
    config.load_files(path)
    return config
