# libPyUtils v2.2

Utilities for easy development of applications in Python.

This project was born from the need to have a set of methods or utilities that facilitate the development of Python applications.

## Utilities
- Create and read YAML files.
- Read a YAML file and convert the content to a string. If the value of a key is encrypted, it replaces it with the legend "Encrypted value", for security reasons.
- Copy a file.
- Remove a file.
- Create and remove folders.
- Rename a file or folder.
- Validate data using a regular expression.
- Converts an amount of time expressed in minutes, hours and/or days into seconds.
- Converts an amount of time expressed in minutes, hours and/or days into a string that represents a date math to do time range searches in ElasticSearch.
- Create and/or convert a list into an object usable by PythonDialog.
- Convert a list of objects to a string.
- Get passphrase for encryption/decryption process of a file.
- Get subdirectories of a folder.
- Get a list of YAML files in a folder.
- Modify permissions of a file or folder. Change of owner, such as, access permissions.
- Get hash of a file (sha256).
- Data encryption and decryption. Use of AES algorithm GCM mode.

# Requirements
- Red Hat 8 or Rocky Linux 8 (Tested on Rocky Linux 8.10)
- Python 3.12
- Python Libraries
  - pycryptodomex
  - PyYAML
  - psutil

**NOTE:** The versions displayed are the versions with which it was tested. This doesn't mean that versions older than these don't work.

# Installation

Copy the "libPyUtils" folder to the following path:

`/usr/local/lib/python3.12/site-packages/`

**NOTE:** The path changes depending on the version of Python used.
