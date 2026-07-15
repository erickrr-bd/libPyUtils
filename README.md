# libPyUtils (v2.3)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Cryptographic Cipher](https://img.shields.io/badge/cipher-AES--GCM%20%28256--bit%29-blueviolet.svg)](https://pycryptodome.readthedocs.io/)
[![Security Hardening](https://img.shields.io/badge/security-Pentest--compliant-brightgreen.svg)](#)

**libPyUtils** is a high-performance, Pentest-hardened system utilities engine written in Python. Serving as the core operational foundation of the application ecosystem, it provides a secure abstraction layer for atomic UNIX file operations, operating system access control lists (ACLs), pure-memory daemon orchestration, and authenticated cryptographic lifecycles.

It replaces standard, vulnerable script templates with hardened Python primitives that systematically prevent code injection, block race conditions, protect system file integrity under heavy load, and isolate cryptographic secrets.

---

## ✨ Features

*   **Command-Injection Mitigation (CWE-78):** Completely replaces unsafe shell pipelines (`os.system`/`os.popen`) with isolated array-based execution matrices (`subprocess` with `shell=False`), structurally blocking OS command injections.
*   **Authenticated Symmetric Encryption (AES-GCM):** Implements industry-standard Authenticated Encryption with Associated Data (AEAD) via 256-bit `AES-GCM` to guarantee both data confidentiality and cryptographic integrity (tamper-proofing).
*   **Atomic Write Staging Architecture:** Employs temporary file buffers (`.tmp`) during structural updates, swapping data blocks atomically via kernel routines (`os.replace`) to eliminate config profile corruption during power drops or process kills.
*   **Zero-Disk I/O Service Telemetry:** Captures detailed system service structures (`systemctl`) and active threading metrics directly into RAM runtime buffers, avoiding redundant disk wear and preventing local race conditions.
*   **Recursive Shoulder-Surfing Scrubber:** Houses data masking engines that traverse structural telemetry trees recursively, blinding raw system bytes or password keys before passing them into interactive user terminal boxes.
*   **Resilient Linux Hardening Hooks:** Wraps native permission transformations (`chmod`/`chown`) in robust validation frameworks, preventing script crashes if target user environments lack specific system users or administrative groups.

---

## 🛠️ Security Hardening (Pentest-Compliant)

Utility modules are primary targets for systemic exploit chains. **libPyUtils** is engineered with zero-trust principles at the operational boundary:
1.  **Shell Decoupling:** By keeping the command interpreter out of the loop, input strings are evaluated strictly as literal parameters by the kernel rather than executable statements. Even if a daemon name contains a malicious payload like `; rm -rf /`, it is rendered entirely benign.
2.  **Cryptographic Cryptcheck:** Legacy ciphers (such as AES-CBC) are vulnerable to padding oracle attacks. Switching to **AES-GCM** ensures that any unauthorized modification of the encrypted configuration files results in an immediate authentication failure, aborting decryption routines before data exposure occurs.
3.  **Secure Descriptor Lifecycles:** File context wrappers (`with`) ensure that system key read descriptors are flushed and closed at the kernel level instantly, even if hardware input/output faults interrupt memory processing.

---

## 📋 API Usage Reference

### Cryptographic & System Operations

| Method | Focus |
| :--- | :--- |
| `encrypt_data(data, passphrase)` | Derives a secure 256-bit key using `SHA256` and returns an authenticated payload tuple: `(ciphertext, nonce, auth_tag)`. |
| `decrypt_data(data, passphrase)` | Re-initializes the GCM context, authenticates the verification tag against tampering, and returns a sanitized UTF-8 string. |
| `create_yaml_file(data, file_path)`| Stages structural data in a temporary block, writing it to disk atomically to prevent partial-write failures. |
| `convert_yaml_to_str(file_path)` | Recursively redacts sensitive credentials keys (`token`, `password`, `key`) or raw binary blocks inside an existing YAML structure before text display. |
| `manage_daemon(name, option)` | Dispatches standard commands (`start`, `restart`, `stop`) to the system manager cleanly using array arguments. |
| `get_detailed_status_by_daemon(name)` | Queries system runtime engines to assemble status reports entirely in memory, removing disk dependencies. |
| `change_owner(path, user, group, mode)` | Maps targeted system names to their numerical IDs safely, enforcing restricted permission structures. |

---

## 🚀 Quick Start Example

Here is how you can perform secure authenticated encryption and manage system components safely:

```python
from libPyUtils import libPyUtils

# Initialize the core utilities toolkit
utils = libPyUtils()

# 1. Hardened Symmetric Data Encryption (AES-GCM)
secret_payload = "SensitiveDBPassword2026!"
passphrase = "MasterSystemKeyPassphrase"

# Automatically returns (encrypted_bytes, nonce, tag)
encrypted_tuple = utils.encrypt_data(secret_payload, passphrase)

# 2. Secure Cryptographic Decryption & Authentication Verification
try:
    decrypted_text = utils.decrypt_data(encrypted_tuple, passphrase)
    print(f"Decryption successful: {decrypted_text}")
except ValueError as e:
    print(f"Alert! Cryptographic tampering detected: {e}")

# 3. Safe System Service Management (Injection-Free)
# Executed via array-based bindings: ['systemctl', 'restart', 'elasticsearch']
exit_code = utils.manage_daemon(daemon_name="elasticsearch", option=2)

if exit_code == 0:
    print("Elasticsearch service restarted safely without shell exposure.")
```

---

📄 Atomic File Execution Verification
When updating cluster structures, libPyUtils ensures that state updates leave zero stray blocks exposed, preventing mid-operation state loss:

```bash
# During active serialization, data scales down cleanly to a transaction file:
/etc/Snap-Tool/configuration/es_conf.yaml.tmp

# Once the transaction concludes, the temporary file replaces the main configuration store:
$ ls -lh /etc/Snap-Tool/configuration/es_conf.yaml
-rw------- 1 snap_tool snap_tool 512 Jul 14 20:42 es_conf.yaml
```
(The system profile remains complete and secure throughout the execution sequence).
