import os
import pathlib
import pytest
import logging

from yes.configuration import YesConfiguration

logging.basicConfig(level=logging.DEBUG)

@pytest.fixture
def yes_sandbox_test_config():
    return YesConfiguration.sandbox_test_from_env()