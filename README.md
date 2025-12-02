# 🔨 libPyUtils v2.2

Modular collection of features and tools designed to make Python application development easier. 

It includes utilities for validation, error handling, automation of common tasks and reusable structures that accelerate the implementation of robust and maintainable solutions.

# ⚙️ Features
- YAML file management (creation, reading, converting to TXT)
- Folder management (creation, rename, delete)
- List and tuple management (convert to string, convert to pythondialog form, convert to pythondialog radiolist or pythondialog checklist)
- File management (copy, delete, change of owner, change of permissions)
- Obtain encryption key for a file
- Validate data using regular expressions
- Convert time to seconds
- Generate lte and gte in date math format
- Demon or service management (start, stop, restart, get current status)
- Thread and process management (Get pid of a process, get number of threads in a process)
- Get hash of a file
- Encrypt and decrypt a string (AES-GCM)

# 📝 Requirements
- Python 3.12+
- Python Libraries
  - [pycryptodomex](https://pypi.org/project/pycryptodome/)
  - [PyYAML](https://pypi.org/project/PyYAML/)
  - [psutil](https://pypi.org/project/psutil/)

# 🛠️ Installation

The installation can be done using a .whl (Wheel) file. To generate a file, you must have the following packaging tools installed:

`pip install setuptools wheel`

The following command is executed from the root of the project:

`python setup.py sdist bdist_wheel`

This action will generate the following files:

`dist/libPyUtils-2.2-py3-none-any.whl`

`dist/libPyUtils-2.2.tar.gz`

It's now possible to install the library using the Wheel file and the pip tool:

`pip3 install libPyUtils-2.2-py3-none-any.whl`
