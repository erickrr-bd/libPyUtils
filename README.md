# libPyUtils v1.2

Utilities for easy development of applications in Python. 

Set of methods or functions that can be used to develop applications in Python.

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
- Obtain the current status of a specific service or daemon.
- Obtain the PID of a specific service or daemon.
- Obtain the number of threads of a specific process.

# Requirements
- CentOS 8, Red Hat 8 or Rocky Linux 8
- Python 3.9
- Python Libraries
  - pycryptodomex == 3.18.0
  - PyYAML == 6.0.1
  - psutil == 5.9.6

**NOTE:** The versions displayed are the versions with which it was tested. This doesn't mean that versions older than these don't work.

# Installation

Copy the "libPyUtils" folder to the following path:

`/usr/local/lib/python3.9/site-packages/`

**NOTE:** The path depends on the Python version.

# Commercial Support
![Tekium](https://github.com/unmanarc/uAuditAnalyzer2/blob/master/art/tekium_slogo.jpeg)

Tekium is a cybersecurity company specialized in red team and blue team activities based in Mexico, it has clients in the financial, telecom and retail sectors.

Tekium is an active sponsor of the project, and provides commercial support in the case you need it.

For integration with other platforms such as the Elastic stack, SIEMs, managed security providers in-house solutions, or for any other requests for extending current functionality that you wish to see included in future versions, please contact us: info at tekium.mx

For more information, go to: https://www.tekium.mx/
