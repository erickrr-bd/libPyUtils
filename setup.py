from pathlib import Path
from setuptools import find_packages, setup

HERE = Path(__file__).parent

VERSION = '1.0'
PACKAGE_NAME = 'libPyUtils' 
AUTHOR = 'Erick Rodríguez'
AUTHOR_EMAIL = 'erickrr.tbd93@gmail.com, erodriguez@tekium.mx' 
URL = 'https://github.com/erickrr-bd/libPyUtils' 

LICENSE = 'GPLv3' 
DESCRIPTION = 'Utilities for Python applications.' 
LONG_DESCRIPTION = (HERE / "README.md").read_text(encoding='utf-8')
LONG_DESC_TYPE = "text/markdown"

INSTALL_REQUIRES = [
      'pyyaml',
      'pycryptodome',
      'tabulate'
      ]

setup(
    name=PACKAGE_NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type=LONG_DESC_TYPE,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    url=URL,
    install_requires=INSTALL_REQUIRES,
    license=LICENSE,
    packages=find_packages(),
    include_package_data=True
)