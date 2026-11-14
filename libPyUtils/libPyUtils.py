"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyUtils
libPyUtils v2.4.0 - November 2026
A high-performance, Pentest-hardened system utilities engine written in Python.
"""
import os
import re
import stat
import hashlib
import tempfile
import subprocess
from pwd import getpwnam
from grp import getgrnam
from urllib.parse import urlparse
from typing import Tuple, Union
from shutil import copy, rmtree
from Cryptodome.Cipher import AES
from psutil import Process, Error as PsutilError
from yaml import load, dump

try:
	from yaml import CSafeLoader as _YamlLoader, CSafeDumper as _YamlDumper
except ImportError:
	from yaml import SafeLoader as _YamlLoader, SafeDumper as _YamlDumper


class libPyUtils:

	# --- Constants -----------------------------------------------------------------------------
	KDF_ITERATIONS = 600_000
	# Format version of the encrypted data (NOT the library version): only change it if the format changes.
	GCM_AAD = b"libPyUtils:fmt1"
	# AADs used by older versions, only accepted by decrypt_data(allow_legacy = True).
	LEGACY_AADS = (b"libPyUtils:v2.3.1", b"")
	MAX_KEY_FILE_SIZE = 4096
	SENSITIVE_WORDS = ("token", "password", "key", "secret")
	SYSTEMCTL = next((p for p in ("/usr/bin/systemctl", "/bin/systemctl") if os.path.exists(p)), "/usr/bin/systemctl")
	DAEMON_REGEX = re.compile(r"[A-Za-z0-9_][A-Za-z0-9@:._-]*")
	TIME_UNITS = {"minutes": ("m", 60), "hours": ("h", 3600), "days": ("d", 86400)}

	# Last error reported by manage_daemon (stderr of systemctl or the reason of the failure).
	last_error = ""


	# --- Internal helpers ----------------------------------------------------------------------
	def zeroize(self, buffer: Union[bytearray, memoryview]) -> None:
		"""
		Method that overwrites the bytes of a mutable buffer in memory with zeros.
		Note: it only works on mutable buffers; immutable bytes/str objects can't be wiped in Python.
		"""
		if buffer:
			buffer[:] = bytes(len(buffer))


	def _zeroize(self, buffer: Union[bytearray, memoryview]) -> None:
		"""
		Alias kept for backwards compatibility. Use zeroize().
		"""
		self.zeroize(buffer)


	def _mask(self, node):
		"""
		Method that recursively masks sensitive data (bytes and sensitive keys).
		"""
		if isinstance(node, dict):
			return {k: "*Encrypted Data*" if isinstance(v, bytes) or any(w in str(k).lower() for w in self.SENSITIVE_WORDS) else self._mask(v) for k, v in node.items()}
		if isinstance(node, list):
			return [self._mask(item) for item in node]
		return "*Encrypted Data*" if isinstance(node, bytes) else node


	def _is_valid_daemon(self, daemon_name) -> bool:
		"""
		Method that validates a daemon's name so it can't be interpreted as a systemctl option.
		"""
		return isinstance(daemon_name, str) and bool(self.DAEMON_REGEX.fullmatch(daemon_name))


	def _get_time_unit(self, unit_time: str, total_time: int) -> Tuple[str, int]:
		"""
		Method that validates a unit of time and its total, and returns (suffix, seconds_per_unit).
		"""
		if unit_time not in self.TIME_UNITS:
			raise ValueError(f"Invalid unit of time '{unit_time}'. Valid values: {', '.join(self.TIME_UNITS)}.")
		if not isinstance(total_time, int) or isinstance(total_time, bool) or total_time < 0:
			raise ValueError(f"Invalid total time '{total_time}'. It must be a non-negative integer.")
		return self.TIME_UNITS[unit_time]


	def _build_aad(self, context: Union[str, bytes]) -> bytes:
		"""
		Method that builds the additional authenticated data (format version + field context).
		The context binds an encrypted value to its field (e.g. "api_key"), so values can't be swapped inside the file.
		"""
		if isinstance(context, str):
			context = context.encode("utf-8")
		return self.GCM_AAD + b"|" + bytes(context)


	def _scan(self, folder_path: str, want_dir: bool, suffix: str = None, exclude_suffix: bool = False) -> list:
		"""
		Method that lists the entries of a folder filtered by type (directory/file) and by suffix.
		A missing folder returns an empty list.
		"""
		try:
			result = []
			with os.scandir(folder_path) as entries:
				for entry in entries:
					if not (entry.is_dir() if want_dir else entry.is_file()):
						continue
					if suffix is not None and entry.name.endswith(suffix) == exclude_suffix:
						continue
					result.append(entry.name)
			return result
		except FileNotFoundError:
			return []
		except Exception as exception:
			raise IOError(f"Failed to scan '{folder_path}': {str(exception)}") from exception


	# --- YAML ----------------------------------------------------------------------------------
	def create_yaml_file(self, data: dict, yaml_file: str) -> None:
		"""
		Method that creates a YAML file (atomic write, temporary file with 0600 permissions).
		If the file already exists, its permissions and owner are preserved.

		Parameters:
			data (dict): Data to save in the file.
			yaml_file (str): YAML file's path.
		"""
		temp_file = None
		try:
			directory = os.path.dirname(os.path.abspath(yaml_file))
			fd, temp_file = tempfile.mkstemp(dir = directory, suffix = ".tmp")
			with os.fdopen(fd, 'w', encoding = "utf-8") as file:
				if os.path.exists(yaml_file):
					current = os.stat(yaml_file)
					os.fchmod(file.fileno(), stat.S_IMODE(current.st_mode))
					try:
						os.fchown(file.fileno(), current.st_uid, current.st_gid)
					except PermissionError:
						pass
				dump(data, file, Dumper = _YamlDumper, default_flow_style = False)
				file.flush()
				os.fsync(file.fileno())
			os.replace(temp_file, yaml_file)
		except Exception as exception:
			if temp_file and os.path.exists(temp_file):
				os.remove(temp_file)
			raise IOError(f"Failed to safely create YAML file '{yaml_file}': {str(exception)}") from exception


	def read_yaml_file(self, yaml_file: str) -> dict:
		"""
		Method that reads and obtains the data stored in a YAML file.

		Parameters:
			yaml_file (str): YAML file.

		Returns:
			data (dict): Data saved to file.
		"""
		try:
			with open(yaml_file, 'r', encoding = "utf-8") as file:
				return load(file, Loader = _YamlLoader) or {}
		except Exception as exception:
			raise IOError(f"Failed to read YAML file '{yaml_file}': {str(exception)}") from exception


	def convert_yaml_to_str(self, yaml_file: str) -> str:
		"""
		Method that converts the data stored in a YAML file into a string (sensitive data masked).

		Parameters:
			yaml_file (str): YAML file.

		Returns:
			data_str (str): String obtained from the conversion.
		"""
		try:
			with open(yaml_file, 'r', encoding = "utf-8") as file:
				data = load(file, Loader = _YamlLoader) or {}
			return dump(self._mask(data), Dumper = _YamlDumper, default_flow_style = False)
		except Exception as exception:
			raise IOError(f"Error converting YAML to string safely: {str(exception)}") from exception


	def convert_yaml_to_txt(self, yaml_file: str, txt_file: str) -> None:
		"""
		Method that converts a YAML file into a TXT file (sensitive data masked, file created with 0600 permissions, symlinks rejected).

		Parameters:
			yaml_file (str): YAML file's path.
			txt_file (str): TXT file's path.
		"""
		try:
			with open(yaml_file, 'r', encoding = "utf-8") as file:
				yaml_data = self._mask(load(file, Loader = _YamlLoader) or {})
			fd = os.open(txt_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
			with os.fdopen(fd, 'w', encoding = "utf-8") as file:
				os.fchmod(file.fileno(), 0o600)
				for key, value in yaml_data.items():
					if isinstance(value, dict):
						for sub_key, sub_value in value.items():
							file.write(f"{sub_key} - {sub_value}\n")
					else:
						file.write(f"{key} : {value}\n")
		except Exception as exception:
			raise IOError(f"Error exporting YAML to TXT: {str(exception)}") from exception


	# --- Files and folders ---------------------------------------------------------------------
	def delete_file(self, file_path: str) -> None:
		"""
		Method that deletes a file (idempotent: a missing file is not an error).

		Parameters:
			file_path (str): Path's file to be deleted.
		"""
		try:
			os.remove(file_path)
		except FileNotFoundError:
			pass
		except Exception as exception:
			raise IOError(f"Failed to delete file '{file_path}': {str(exception)}") from exception


	def create_folder(self, folder_path: str) -> None:
		"""
		Method that creates a folder (0700 permissions; use change_owner to relax them if needed).

		Parameters:
			folder_path (str): Path's folder to be created.
		"""
		try:
			os.makedirs(folder_path, mode = 0o700, exist_ok = True)
		except Exception as exception:
			raise IOError(f"Failed to create folder '{folder_path}': {str(exception)}") from exception


	def rename_file_or_folder(self, original_name: str, new_name: str) -> None:
		"""
		Method that renames a file or folder. A missing source raises IOError.
		Note: on POSIX systems an existing destination is silently overwritten.

		Parameters:
			original_name: Name of the file or folder to rename.
			new_name: New name of the file or folder.
		"""
		try:
			os.rename(original_name, new_name)
		except Exception as exception:
			raise IOError(f"Failed to rename '{original_name}' to '{new_name}': {str(exception)}") from exception


	def delete_folder(self, folder_path: str, base_dir: str) -> None:
		"""
		Method that deletes a folder, only if it is inside base_dir (and it is not base_dir itself).

		Parameters:
			folder_path (str): Path's folder.
			base_dir (str): Directory that must contain the folder to delete.
		"""
		real_path = os.path.realpath(folder_path)
		base = os.path.realpath(base_dir)
		if real_path == base or os.path.commonpath([real_path, base]) != base:
			raise ValueError(f"Refusing to delete '{real_path}': it is not inside '{base}'.")
		try:
			rmtree(real_path)
		except FileNotFoundError:
			pass
		except Exception as exception:
			raise IOError(f"Failed to force-delete folder '{folder_path}': {str(exception)}") from exception


	def get_enabled_subdirectories(self, folder_path: str) -> list:
		"""
		Method that obtains enabled subdirectories from a specific directory.

		Parameters:
			folder_path (str): Path's folder.

		Returns:
			subdirectories (list): Subdirectories' list.
		"""
		return self._scan(folder_path, True, ".disabled", exclude_suffix = True)


	def get_disabled_subdirectories(self, folder_path: str) -> list:
		"""
		Method that obtains disabled subdirectories from a specific directory.

		Parameters:
			folder_path (str): Path's folder.

		Returns:
			subdirectories (list): Subdirectories' list.
		"""
		return self._scan(folder_path, True, ".disabled")


	def get_yaml_files_in_folder(self, folder_path: str) -> list:
		"""
		Method that obtains the names of YAML files stored in a specific path.

		Parameters:
			folder_path (str): Path where the YAML files will be listed.

		Returns:
			yaml_files (list): List with the names of the YAML files.
		"""
		return self._scan(folder_path, False, ".yaml")


	def get_disabled_files_in_folder(self, folder_path: str) -> list:
		"""
		Method that obtains the disabled files' names stored in a specific path.

		Parameters:
			folder_path (str): Path where the files will be searched for.

		Returns:
			disabled_files (list): List with the disabled files' names.
		"""
		return self._scan(folder_path, False, ".disabled")


	def copy_file(self, source: str, destination: str) -> None:
		"""
		Method that copies a file.

		Parameters:
			source (str): Source file.
			destination (str): Destination folder.
		"""
		try:
			copy(source, destination)
		except FileNotFoundError as exception:
			raise FileNotFoundError(f"Source file '{source}' or destination '{destination}' does not exist.") from exception
		except Exception as exception:
			raise IOError(f"Failed to copy file from '{source}' to '{destination}': {str(exception)}") from exception


	def change_owner(self, path: str, user: str, group: str, mode: str) -> None:
		"""
		Method that changes the owner of a folder and/or file (operates on a descriptor, rejects symlinks).

		Parameters:
			path (str): Folder and/or file.
			user (str): Owner user.
			group (str): Owner group.
			mode (str): New permissions (octal string, e.g. "640").
		"""
		try:
			uid = getpwnam(user).pw_uid
			gid = getgrnam(group).gr_gid
			fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
			try:
				os.fchown(fd, uid, gid)
				os.fchmod(fd, int(mode, base = 8))
			finally:
				os.close(fd)
		except KeyError as ke:
			raise KeyError(f"System configuration error: User '{user}' or Group '{group}' does not exist on this OS. Details: {str(ke)}") from ke
		except Exception as exception:
			raise OSError(f"Failed to apply ACL security permissions on '{path}': {str(exception)}") from exception


	# --- Key file / passphrase -----------------------------------------------------------------
	def get_passphrase(self, key_file: str, owner: str = None) -> bytearray:
		"""
		Method that reads the passphrase from a key file, verifying its security (regular file, no symlink,
		owned by root, the current user or the expected owner, permissions 0600/0400, not empty, reasonable size).
		Returns a bytearray so it can be wiped from memory afterwards.

		Parameters:
			key_file (str): Key file's path.
			owner (str): Name of the user that is expected to own the key file (optional).

		Returns:
			passphrase (bytearray): Passphrase read from the file.
		"""
		allowed_uids = {0, os.geteuid()}
		if owner:
			try:
				allowed_uids.add(getpwnam(owner).pw_uid)
			except KeyError as exception:
				raise KeyError(f"User '{owner}' does not exist on this OS.") from exception
		try:
			fd = os.open(key_file, os.O_RDONLY | os.O_NOFOLLOW)
		except FileNotFoundError as exception:
			raise IOError(f"Key file '{key_file}' doesn't exist.") from exception
		except OSError as exception:
			raise IOError(f"Cannot open key file '{key_file}' (symlinks are rejected): {str(exception)}") from exception
		with os.fdopen(fd, "rb") as file:
			file_stat = os.fstat(file.fileno())
			if not stat.S_ISREG(file_stat.st_mode):
				raise PermissionError(f"'{key_file}' is not a regular file.")
			if file_stat.st_uid not in allowed_uids:
				raise PermissionError(f"'{key_file}' has an unexpected owner (uid {file_stat.st_uid}).")
			file_mode = stat.S_IMODE(file_stat.st_mode)
			if file_mode & 0o077 != 0:
				raise PermissionError(
					f"Insecure permissions ({oct(file_mode)}) on '{key_file}'. "
					f"It must be accessible only by the owner (e.g. 0600)."
				)
			if not 0 < file_stat.st_size <= self.MAX_KEY_FILE_SIZE:
				raise ValueError(f"Key file '{key_file}' has an invalid size ({file_stat.st_size} bytes).")
			try:
				buffer = bytearray(file_stat.st_size)
				read_bytes = file.readinto(buffer)
				del buffer[read_bytes:]
			except OSError as exception:
				raise IOError(f"Critical: Failed to read key_file '{key_file}': {str(exception)}") from exception
		whitespace = b" \t\r\n"
		while buffer and buffer[-1] in whitespace:
			buffer.pop()
		start = 0
		while start < len(buffer) and buffer[start] in whitespace:
			start += 1
		if start:
			del buffer[:start]
		if not buffer:
			raise ValueError(f"Key file '{key_file}' is empty.")
		return buffer


	# --- Validations and conversions -----------------------------------------------------------
	def get_str_from_list(self, list_to_convert: list, title: str) -> str:
		"""
		Method converts a list in a string.

		Parameters:
			list_to_convert (list): List to convert.
			title (str): Title displayed.

		Returns:
			text (str): String obtained from the conversion.
		"""
		if not list_to_convert:
			return f"\n{title}\n\n(No items selected)"
		return f"\n{title}\n" + "".join(f"\n- {item}" for item in list_to_convert)


	def validate_data_regex(self, data, regex) -> bool:
		"""
		Method that validates data using a regular expression (the whole string must match).

		Parameters:
			data (int, str, double): Data to validate.
			regex (regular expression): Regular expression that validates the data.

		Returns:
			is_valid (bool): True if the data is valid, False otherwise.
		"""
		return bool(regex.fullmatch(str(data)))


	def validate_https_urls(self, urls: Union[dict, list]) -> bool:
		"""
		Method that validates whether all the entered URLs use HTTPS.

		Parameters:
			urls (dict, list): URLs to validate.

		Returns:
			(bool): True if all URLs use HTTPS, false otherwise.
		"""
		if not urls:
			return False
		for host in urls:
			if not isinstance(host, str):
				return False
			try:
				parsed = urlparse(host.strip())
			except ValueError:
				return False
			if parsed.scheme != "https" or not parsed.netloc:
				return False
		return True


	def validate_https_or_http(self, es_host: Union[dict, list]) -> bool:
		"""
		Alias kept for backwards compatibility. Use validate_https_urls().
		"""
		return self.validate_https_urls(es_host)


	def generate_tuple_to_form(self, tuple_length: int, text: str) -> tuple:
		"""
		Method that generates a tuple for a pythondialog form.

		Parameters:
			tuple_length (int): Tuple length.
			text (str): Text to be displayed.

		Returns:
			tuple_to_form (tuple): Tuple for pythondialog form.
		"""
		return [
			(f"{text} {i + 1}:", i + 1, 5, "", i + 1, 20, 30, 100)
			for i in range(tuple_length)
		]


	def convert_list_to_tuple(self, list_to_convert: list, text : str) -> tuple:
		"""
		Method that converts a list into a tuple for a pythondialog form.

		Parameters:
			list_to_convert (list): List to convert.
			text (str): Text to be displayed.

		Returns:
			tuple_to_form (tuple): Tuple for pythondialog form.
		"""
		return [
			(f"{text} {i + 1}:", i + 1, 5, item, i + 1, 20, 30, 100)
			for i, item in enumerate(list_to_convert)
		]


	def convert_list_to_tuple_rc(self, list_to_convert: list, text: str) -> tuple:
		"""
		Method that converts a list into a tuple for a pythondialog radiolist or pythondialog checklist.

		Parameters:
			list_to_convert (list): List to convert.
			text (str): Text to be displayed.

		Returns:
			tuple_to_rc (tuple): Tuple for pythondialog radiolist or pythondialog checklist.
		"""
		return [(item, text, 0) for item in list_to_convert]


	def convert_time_to_seconds(self, unit_time: str, total_time: int) -> int:
		"""
		Method that converts a quantity expressed in minutes, hours or days into seconds.
		Raises ValueError if the unit or the total are invalid.

		Parameters:
			unit_time (str): Unit of time in which the total is expressed (minutes, hours or days).
			total_time (int): Total time to convert.

		Returns:
			total_seconds (int): Result of conversion to seconds.
		"""
		_, seconds_per_unit = self._get_time_unit(unit_time, total_time)
		return total_time * seconds_per_unit


	def get_gte_date(self, unit_time: str, total_time: int) -> str:
		"""
		Method that converts an amount of time expressed in minutes, hours or days into the gte value expressed in date math format
		(Elasticsearch syntax; it is NOT valid for the NVD API).
		Raises ValueError if the unit or the total are invalid.

		Parameters:
			unit_time (str): Unit of time in which the total is expressed (minutes, hours or days).
			total_time (int): Total time to convert.

		Returns:
			date_string (str): String in date math format.
		"""
		suffix, _ = self._get_time_unit(unit_time, total_time)
		return f"now-{total_time}{suffix}/{suffix}"


	def get_lte_date(self, unit_time: str) -> str:
		"""
		Method that converts an amount of time expressed in minutes, hours or days into the lte value expressed in date math format.
		Raises ValueError if the unit is invalid.

		Parameters:
			unit_time (str): Unit of time in which the total is expressed (minutes, hours or days).

		Returns:
			date_string (str): String in date math format.
		"""
		suffix, _ = self._get_time_unit(unit_time, 0)
		return f"now/{suffix}"


	# --- Daemons -------------------------------------------------------------------------------
	def manage_daemon(self, daemon_name: str, option: int) -> int:
		"""
		Method that manages a daemon or service (start, restart, and stop).
		If it fails, the reason is available in self.last_error.

		Parameters:
			daemon_name (str): Daemon's name.
			option (int): Option to perform (1.- Start daemon, 2.- Restart daemon, 3.- Stop daemon)

		Returns:
			result (int): Result of the command execution (0 = success).
		"""
		self.last_error = ""
		action = {1: "start", 2: "restart", 3: "stop"}.get(option)
		if not action or not self._is_valid_daemon(daemon_name):
			self.last_error = "Invalid action or daemon name."
			return -1
		try:
			result = subprocess.run([self.SYSTEMCTL, "--no-ask-password", action, "--", daemon_name], capture_output = True, text = True, check = False, timeout = 30)
			self.last_error = result.stderr.strip()
			return result.returncode
		except subprocess.TimeoutExpired:
			self.last_error = "Timeout."
			return -1
		except Exception as exception:
			self.last_error = str(exception)
			return -1


	def get_detailed_status_by_daemon(self, daemon_name: str, file_name = None) -> str:
		"""
		Method that gets the current detailed status of a daemon.

		Parameters:
			daemon_name (str): Daemon's name.
			file_name: Unused. Kept only for backwards compatibility.

		Returns:
			service_status (str): Detailed status of the service or daemon.
		"""
		if not self._is_valid_daemon(daemon_name):
			return "Error retrieving detailed status: invalid daemon name."
		try:
			result = subprocess.run([self.SYSTEMCTL, "-l", "--no-pager", "status", "--", daemon_name], capture_output = True, text = True, check = False, timeout = 15)
			status_text = "Service is running!\n" if result.returncode == 0 else "Service is not running!\n"
			return f"{status_text}Detailed service status:\n{result.stdout}"
		except Exception as exception:
			return f"Error retrieving detailed status: {str(exception)}"


	def get_status_by_daemon(self, daemon_name: str) -> str:
		"""
		Method that obtains the current status of a daemon.

		Parameters:
			daemon_name (str): Daemon's name.

		Returns:
			daemon_status (str): Current status of the daemon.
		"""
		if not self._is_valid_daemon(daemon_name):
			return "Not running"
		try:
			result = subprocess.run([self.SYSTEMCTL, "is-active", "--quiet", "--", daemon_name], check = False, timeout = 15)
			return "Running" if result.returncode == 0 else "Not running"
		except Exception:
			return "Not running"


	def get_pid_by_daemon(self, daemon_name: str) -> int:
		"""
		Method that obtains the PID of a daemon.

		Parameters:
			daemon_name (str): Name of the daemon or service.

		Returns:
			pid (int): Daemon's PID.
		"""
		if not self._is_valid_daemon(daemon_name):
			return 0
		try:
			result = subprocess.run([self.SYSTEMCTL, "show", "--property", "MainPID", "--value", "--", daemon_name], capture_output = True, text = True, check = False, timeout = 15)
			pid_str = result.stdout.strip()
			return int(pid_str) if pid_str and pid_str != "0" else 0
		except Exception:
			return 0


	def get_threads_by_pid(self, pid: int) -> int:
		"""
		Method that obtains the total number of threads running in a process based on its PID.

		Parameters:
			pid (int): Daemon's PID.

		Returns:
			total_threads (int): Total number of threads running on the PID.
		"""
		if not isinstance(pid, int) or pid <= 0:
			return 0
		try:
			return int(Process(pid).num_threads())
		except PsutilError:
			return 0


	# --- Encryption ----------------------------------------------------------------------------
	def encrypt_data(self, data: Union[str, bytearray], passphrase: Union[str, bytearray], context: Union[str, bytes] = b"") -> Tuple[bytes, bytes, bytes, bytes]:
		"""
		Method that encrypts data with AES-256-GCM, deriving the key from the passphrase with PBKDF2-HMAC-SHA256.

		Parameters:
			data (str, bytearray): Data to encrypt.
			passphrase (str, bytearray): Passphrase used to derive the key.
			context (str, bytes): Field the value belongs to (e.g. "cve_alert:api_key"). It is authenticated, so
			                      the same context must be given to decrypt_data.

		Returns:
			(tuple): (ciphertext, nonce, auth_tag, salt)
		"""
		salt = os.urandom(16)
		pass_bytes = bytearray(passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase)
		data_bytes = bytearray(data.encode("utf-8") if isinstance(data, str) else data)
		derived_key = None
		try:
			derived_key = bytearray(hashlib.pbkdf2_hmac("sha256", pass_bytes, salt, self.KDF_ITERATIONS, dklen = 32))
			aes = AES.new(derived_key, AES.MODE_GCM, nonce = os.urandom(12))
			aes.update(self._build_aad(context))
			ciphertext, auth_tag = aes.encrypt_and_digest(data_bytes)
			return (ciphertext, aes.nonce, auth_tag, salt)
		except Exception as exception:
			raise ValueError(f"Encryption process failed: {str(exception)}") from exception
		finally:
			self.zeroize(pass_bytes)
			self.zeroize(data_bytes)
			if derived_key is not None:
				self.zeroize(derived_key)


	def decrypt_data(self, data: Tuple[bytes, bytes, bytes, bytes], passphrase: Union[str, bytearray], allow_legacy: bool = False, context: Union[str, bytes] = b"") -> str:
		"""
		Method that decrypts and authenticates data encrypted with encrypt_data.

		Parameters:
			data (tuple): (ciphertext, nonce, auth_tag, salt)
			passphrase (str, bytearray): Passphrase used to derive the key.
			allow_legacy (bool): If True, data encrypted by older versions (v2.3.1 AAD or without AAD) can also be decrypted.
			                     Use it only to migrate old data, then re-encrypt it with the context.
			context (str, bytes): Field the value belongs to. It must match the one used to encrypt.

		Returns:
			plaintext (str): Decrypted data.
		"""
		try:
			ciphertext, nonce, auth_tag, salt = data
		except (ValueError, TypeError) as exception:
			raise ValueError("Decryption failed: Invalid ciphertext structure.") from exception
		pass_bytes = bytearray(passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase)
		derived_key = None
		try:
			derived_key = bytearray(hashlib.pbkdf2_hmac("sha256", pass_bytes, salt, self.KDF_ITERATIONS, dklen = 32))
			candidates = [self._build_aad(context)]
			if allow_legacy:
				candidates.extend(self.LEGACY_AADS)
			plaintext = None
			for aad in candidates:
				aes = AES.new(derived_key, AES.MODE_GCM, nonce = nonce)
				aes.update(aad)
				try:
					plaintext = aes.decrypt_and_verify(ciphertext, auth_tag)
					break
				except ValueError:
					continue
			if plaintext is None:
				raise ValueError("MAC check failed (wrong passphrase, wrong context or tampered data).")
			return plaintext.decode("utf-8")
		except Exception as exception:
			raise ValueError(f"Decryption / Authentication check failed: {str(exception)}") from exception
		finally:
			self.zeroize(pass_bytes)
			if derived_key is not None:
				self.zeroize(derived_key)