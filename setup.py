from pathlib import Path
from setuptools import find_packages, setup

HERE = Path(__file__).parent

VERSION = '2.3'
PACKAGE_NAME = 'libPyUtils' 
AUTHOR = 'Erick Roberto Rodríguez Rodriguez'
AUTHOR_EMAIL = 'erickrr.tbd93@gmail.com, erodriguez@tekium.mx' 
URL = 'https://github.com/erickrr-bd/libPyUtils' 

LICENSE = 'GPLv3' 
DESCRIPTION = 'A high-performance, Pentest-hardened system utilities engine written in Python.' 
LONG_DESCRIPTION = (HERE / "README.md").read_text(encoding = 'utf-8')
LONG_DESC_TYPE = "text/markdown"

INSTALL_REQUIRES = [
      'pycryptodomex',
      'psutil',
      'PyYAML'
      ]

setup(
    name = PACKAGE_NAME,
    version = VERSION,
    description = DESCRIPTION,
    long_description = LONG_DESCRIPTION,
    long_description_content_type = LONG_DESC_TYPE,
    author = AUTHOR,
    author_email = AUTHOR_EMAIL,
    url = URL,
    install_requires = INSTALL_REQUIRES,
    license = LICENSE,
    packages = find_packages(),
    include_package_data = True
)