# libPyUtils

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Version](https://img.shields.io/badge/version-2.4.0-green)

A hardened system utilities engine for Python: safe YAML configuration files, file and folder helpers, authenticated encryption of secrets, `systemd` service management and small validation helpers.

Every function that touches the file system, a secret or a system command was written with the failure modes of a penetration test in mind: no shell, no symbolic links followed, atomic writes, strict permissions and validated input.

It is the foundation of the CVE-Alert suite ([CVE-Alert](https://github.com/erickrr-bd/CVE-Alert), [libPyDialog](https://github.com/erickrr-bd/libPyDialog), [libPyAgentConfiguration](https://github.com/erickrr-bd/libPyAgentConfiguration)).

## Features

- **YAML**: atomic writes (temporary file, `fsync`, `os.replace`), existing owner and permissions preserved, safe loader and dumper only, secrets masked when displayed or exported.
- **Secrets**: AES-256-GCM with a key derived by PBKDF2-HMAC-SHA256 (600,000 iterations), a random salt and nonce per value, and **authenticated context** so an encrypted value cannot be moved to another field.
- **Key file handling**: refuses symbolic links, wrong owners, loose permissions, empty or oversized files, and returns the passphrase as a `bytearray` you can wipe.
- **Services**: start, restart, stop and inspect `systemd` units without a shell, with validated names, absolute `systemctl` path and timeouts.
- **Files and folders**: creation with `0700`, descriptor-based `chown`/`chmod` that rejects symlinks, folder deletion restricted to a base directory.
- **Helpers**: regex validation, HTTPS URL validation, time conversions and tuple builders for `pythondialog` forms.

## Requirements

| Requirement | Notes |
| --- | --- |
| Python | 3.10 or newer (tested with 3.13) |
| Linux with `systemd` | For the service functions (`/usr/bin/systemctl` or `/bin/systemctl`) |
| [PyYAML](https://pypi.org/project/PyYAML/) | Uses the C loader when libyaml is available |
| [pycryptodomex](https://pypi.org/project/pycryptodomex/) | Provides `Cryptodome.Cipher.AES` |
| [psutil](https://pypi.org/project/psutil/) | Thread count of a process |

## Installation

```bash
git clone https://github.com/erickrr-bd/libPyUtils.git
pip install pyyaml pycryptodomex psutil
```

Copy `libPyUtils.py` into your project, or add the cloned folder to your `PYTHONPATH`.

## Quick start

```python
from libPyUtils import libPyUtils

utils = libPyUtils()

# --- Encrypt a secret and store it in a YAML file ---------------------------
passphrase = utils.get_passphrase("/opt/MyApp/configuration/key", owner = "my_user")
try:
	token = utils.encrypt_data("123456789:AAH...", passphrase, context = "my_app:telegram_bot_token")
finally:
	utils.zeroize(passphrase)          # overwrite the passphrase in memory

utils.create_yaml_file({"telegram_bot_token": token}, "/opt/MyApp/configuration/app.yaml")
utils.change_owner("/opt/MyApp/configuration/app.yaml", "my_user", "my_group", "600")

# --- Read it back -----------------------------------------------------------
data = utils.read_yaml_file("/opt/MyApp/configuration/app.yaml")
passphrase = utils.get_passphrase("/opt/MyApp/configuration/key", owner = "my_user")
try:
	plain = utils.decrypt_data(data["telegram_bot_token"], passphrase, context = "my_app:telegram_bot_token")
finally:
	utils.zeroize(passphrase)

# --- Manage a service -------------------------------------------------------
if utils.manage_daemon("my-app.service", 2) != 0:    # 1 = start, 2 = restart, 3 = stop
	print("Could not restart the service:", utils.last_error)
```

## Encryption

`encrypt_data` returns a tuple `(ciphertext, nonce, auth_tag, salt)`. Saved with `create_yaml_file`, it becomes a list of four `!!binary` values that `read_yaml_file` loads back unchanged.

The **context** is part of the authenticated data of AES-GCM. Use one value per field (for example `"my_app:api_key"`, `"my_app:telegram_bot_token"`): decrypting with a different context, or after two encrypted values were swapped in the file, fails the authentication check with a `ValueError`.

| Parameter | Description |
| --- | --- |
| `data` | `str` or `bytearray` to encrypt. |
| `passphrase` | `str` or `bytearray`; use the one returned by `get_passphrase`. |
| `context` | Field the value belongs to. It must be the same when decrypting. |
| `allow_legacy` (`decrypt_data`) | Also accept values encrypted by versions before 2.4.0. Use it only to migrate old data, then re-encrypt it. |

`decrypt_data` returns a `str`. Data is encrypted with a 96-bit nonce, a 128-bit tag and a new random salt per value.

## The key file

`get_passphrase(key_file, owner = None)` returns the passphrase only if the file:

- is a regular file (symbolic links are rejected),
- is owned by root, by the current user or by `owner`,
- is not accessible by group or others (for example `0600` or `0400`),
- is not empty and not larger than 4 KB.

Leading and trailing whitespace is removed. The result is a `bytearray`: wipe it with `zeroize` when you are done. Python cannot guarantee that every copy of an immutable `str` is erased, so this is best-effort hardening.

## API reference

### YAML

| Method | Description |
| --- | --- |
| `create_yaml_file(data, yaml_file)` | Atomic write. If the file exists, its permissions and owner are preserved (owner only when running as root); otherwise it is created `0600`. |
| `read_yaml_file(yaml_file)` | Reads a YAML file with the safe loader. Returns `{}` for an empty file. |
| `convert_yaml_to_str(yaml_file)` | Returns the YAML text with binary values and keys that contain `token`, `password`, `key` or `secret` masked. |
| `convert_yaml_to_txt(yaml_file, txt_file)` | Exports the (masked) data to a text file created `0600`. Symbolic links at the destination are rejected. |

### Files and folders

| Method | Description |
| --- | --- |
| `create_folder(folder_path)` | Creates a folder (and parents) with `0700`. |
| `delete_file(file_path)` | Deletes a file. A missing file is not an error. |
| `rename_file_or_folder(original, new)` | Renames. A missing source raises `IOError`. An existing destination is overwritten (POSIX). |
| `delete_folder(folder_path, base_dir)` | Recursively deletes a folder **only if it is inside `base_dir`** (and is not `base_dir` itself). Symlinks are resolved first. |
| `copy_file(source, destination)` | Copies a file. |
| `change_owner(path, user, group, mode)` | `chown` + `chmod` through a file descriptor; symlinks are rejected. `mode` is an octal string such as `"640"`. |
| `get_enabled_subdirectories(folder)` / `get_disabled_subdirectories(folder)` | Subdirectories whose name does not / does end in `.disabled`. A missing folder returns `[]`. |
| `get_yaml_files_in_folder(folder)` | Names of the `*.yaml` files. |
| `get_disabled_files_in_folder(folder)` | Names of the `*.disabled` files. |

### Key file and encryption

| Method | Description |
| --- | --- |
| `get_passphrase(key_file, owner = None)` | Reads the passphrase as a `bytearray` (see above). |
| `encrypt_data(data, passphrase, context = b"")` | AES-256-GCM encryption. |
| `decrypt_data(data, passphrase, allow_legacy = False, context = b"")` | Decrypts and authenticates. Raises `ValueError` on any failure. |
| `zeroize(buffer)` | Overwrites a `bytearray` or `memoryview` with zeros. |

### Services (`systemd`)

| Method | Returns | Description |
| --- | --- | --- |
| `manage_daemon(daemon_name, option)` | `int` | `1` start, `2` restart, `3` stop. Returns the `systemctl` exit code (`0` = success), or `-1` for invalid input, timeout or error. The reason is stored in `last_error`. |
| `get_status_by_daemon(daemon_name)` | `str` | `"Running"` or `"Not running"`. |
| `get_detailed_status_by_daemon(daemon_name)` | `str` | Output of `systemctl status`, with a "running / not running" header. |
| `get_pid_by_daemon(daemon_name)` | `int` | Main PID, or `0`. |
| `get_threads_by_pid(pid)` | `int` | Number of threads of a process, or `0`. |

Service names are validated (`[A-Za-z0-9_][A-Za-z0-9@:._-]*`), `systemctl` is called by absolute path with a list of arguments (never through a shell), the name is passed after `--` so it can never be read as an option, and every call has a timeout (30 s to change a service, 15 s for the rest). `manage_daemon` also passes `--no-ask-password`, so an unprivileged caller gets an error instead of a hidden prompt.

Starting or stopping system services needs root, or a polkit rule that allows your user to manage that unit.

### Validation and conversion

| Method | Description |
| --- | --- |
| `validate_data_regex(data, regex)` | `True` if the **whole** string matches the compiled regular expression. |
| `validate_https_urls(urls)` | `True` if the list is not empty and every URL uses `https`. |
| `convert_time_to_seconds(unit, total)` | `unit` is `"minutes"`, `"hours"` or `"days"`. Raises `ValueError` otherwise. |
| `get_gte_date(unit, total)` / `get_lte_date(unit)` | Elasticsearch date-math strings such as `now-7d/d`. They are **not** ISO-8601 dates: do not send them to APIs that expect real dates. |
| `get_str_from_list(items, title)` | Formats a list as text for a dialog. |
| `generate_tuple_to_form(length, text)` | Builds `length` empty rows for a `pythondialog` form. |
| `convert_list_to_tuple(items, text)` | Builds form rows pre-filled with `items`. |
| `convert_list_to_tuple_rc(items, text)` | Builds `(tag, description, status)` rows for radiolists and checklists. |

## Security notes

- No function uses `shell = True`, `eval` or `exec`, and no YAML data is loaded with an unsafe loader.
- Files holding secrets are created with `0600`, replaced atomically, and protected against symlink attacks (`O_NOFOLLOW`) where they are opened for writing or changing ownership.
- Keep the key file apart from the encrypted data (different directory, `0700`) and out of version control and backups that also contain the configuration: anyone with both can decrypt it.
- `decrypt_data(..., allow_legacy = True)` weakens the protection against swapped values. Enable it only while migrating.
- Applications that run as root should never build a path from user input without validating it first. `delete_folder` requires a `base_dir` for that reason.

## Migrating from 2.3.1

Version 2.4.0 contains breaking changes:

- **Encrypted data format.** The authenticated data is now `libPyUtils:fmt1|<context>` instead of the library version (`libPyUtils:v2.3.1`), so upgrading the library never invalidates your secrets again. Values encrypted by 2.3.1 decrypt only with `allow_legacy = True`; re-encrypt them with a `context`.
- **`delete_folder(folder_path, base_dir)`** now requires `base_dir` and refuses anything outside it.
- **`rename_file_or_folder`** raises `IOError` when the source does not exist (it used to ignore it silently).
- **`get_passphrase`** verifies the owner (root, the current user or `owner`), rejects empty and oversized files, and accepts the new `owner` argument.
- **`create_yaml_file`** also preserves the owner of the file it replaces, so a root process no longer changes it to `root:root`.
- **`manage_daemon`** records the failure reason in `last_error` and passes `--no-ask-password`.
- **`zeroize`** is now public (`_zeroize` remains as an alias).
- **`validate_https_urls`** is the new name of `validate_https_or_http`, which remains as an alias.
- **`generate_tuple_to_form`** now builds empty rows instead of rows pre-filled with the label text.
- **`convert_yaml_to_txt`** rejects symbolic links at the destination.
- **New encryptions use a 12-byte nonce** (previously 16). Older values still decrypt.

## Author

**Erick Roberto Rodriguez Rodriguez**
[erodriguez@tekium.mx](mailto:erodriguez@tekium.mx) · [erickrr.tbd93@gmail.com](mailto:erickrr.tbd93@gmail.com) · [GitHub](https://github.com/erickrr-bd/libPyUtils)

