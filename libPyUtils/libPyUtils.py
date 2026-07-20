"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyUtils
libPyUtils v2.3 - July 2026
Modular collection of features and tools designed to make Python application development easier.
"""
import subprocess
from glob import glob
from pwd import getpwnam
from grp import getgrnam
from hashlib import sha256
from psutil import Process, NoSuchProcess
from shutil import copy, rmtree
from Cryptodome.Cipher import AES
from yaml import safe_load, safe_dump
from os import chown, chmod, path, remove, rename, mkdir, scandir, replace

class libPyUtils:

	def create_yaml_file(self, data: dict, yaml_file: str) -> None:
		"""
		Method that creates a YAML file.

		Parameters:
			data (dict): Data to save in the file.
			yaml_file (str): YAML file's path.
		"""
		temp_file = f"{yaml_file}.tmp"
		try:
			with open(temp_file, 'w') as file:
				safe_dump(data, file, default_flow_style = False)
			replace(temp_file, yaml_file)
		except Exception as exception:
			if path.exists(temp_file):
				remove(temp_file)
			raise IOError(f"Failed to safely create YAML file '{yaml_file}': {str(exception)}")


	def read_yaml_file(self, yaml_file: str) -> dict:
		"""
		Method that reads and obtains the data stored in a YAML file.

		Parameters:
			yaml_file (str): YAML file.

		Returns:
			data (dict): Data saved to file.
		"""
		try:
			with open(yaml_file, 'r') as file:
				return safe_load(file) or {}
		except Exception as exception:
			raise IOError(f"Failed to read YAML file '{yaml_file}': {str(exception)}")


	def delete_file(self, file_path: str) -> None:
		"""
		Method that deletes a file.

		Parameters:
			file_path (str): Path's file to be deleted.
		"""
		try:
			if path.exists(file_path):
				remove(file_path)
		except Exception as exception:
			raise IOError(f"Failed to delete file '{file_path}': {str(exception)}")


	def create_folder(self, folder_path: str) -> None:
		"""
		Method that creates a folder.

		Parameters:
			folder_path (str): Path's folder to be created.
		"""
		try:
			if not path.isdir(folder_path):
				mkdir(folder_path)
		except Exception as exception:
			raise IOError(f"Failed to create folder '{folder_path}': {str(exception)}")


	def rename_file_or_folder(self, original_name: str, new_name: str) -> None:
		"""
		Method that renames a file or folder.

		Parameters:
			original_name: Name of the file or folder to rename.
			new_name: New name of the file or folder.
		"""
		try:
			if path.exists(original_name):
				rename(original_name, new_name)
		except Exception as exception:
			raise IOError(f"Failed to rename '{original_name}' to '{new_name}': {str(exception)}")


	def delete_folder(self, folder_path: str) -> None:
		"""
		Method that deletes a specific folder.

		Parameters:
			folder_path (str): Path's folder.
		"""
		try:
			if path.exists(folder_path):
				rmtree(folder_path)
		except Exception as exception:
			raise IOError(f"Failed to force-delete folder '{folder_path}': {str(exception)}")


	def get_enabled_subdirectories(self, folder_path: str) -> list:
		"""
		Method that obtains enabled subdirectories from a specific directory.

		Parameters:
			folder_path (str): Path's folder.

		Returns:
			subdirectories (list): Subdirectories' list.
		"""
		try:
			if not path.exists(folder_path):
				return []
			with scandir(folder_path) as directories:
				subdirectories = [directory.name for directory in directories if directory.is_dir() and not directory.name.endswith(".disabled")]
				return subdirectories
		except Exception as exception:
			raise IOError(f"Failed to scan subdirectories in '{folder_path}': {str(exception)}")


	def get_disabled_subdirectories(self, folder_path: str) -> list:
		"""
		Method that obtains disabled subdirectories from a specific directory.

		Parameters:
			folder_path (str): Path's folder.

		Returns:
			subdirectories (list): Subdirectories' list.
		"""
		try:
			if not path.exists(folder_path):
				return []
			with scandir(folder_path) as directories:
				subdirectories = [directory.name for directory in directories if directory.is_dir() and directory.name.endswith(".disabled")]
				return subdirectories
		except Exception as exception:
			raise IOError(f"Error scanning disabled subdirectories: {str(exception)}")


	def get_yaml_files_in_folder(self, folder_path: str) -> list:
		"""
		Method that obtains the names of YAML files stored in a specific path.

		Parameters:
			folder_path (str): Path where the YAML files will be listed.

		Returns:
			yaml_files (list): List with the names of the YAML files.
		"""
		try:
			yaml_files = [path.basename(yaml_file) for yaml_file in glob(f"{folder_path}/*.yaml")]
			return yaml_files
		except Exception as exception:
			raise IOError(f"Error listing YAML files: {str(exception)}")


	def get_disabled_files_in_folder(self, folder_path: str) -> list:
		"""
		Method that obtains the disabled files' names stored in a specific path.

		Parameters:
			folder_path (str): Path where the files will be searched for.

		Returns:
			disabled_files (list): List with the disabled files' names.
		"""
		try:
			disabled_files = [path.basename(disabled_file) for disabled_file in glob(f"{folder_path}/*.disabled")]
			return disabled_files
		except Exception as exception:
			raise IOError(f"Error listing disabled files: {str(exception)}")


	def convert_yaml_to_str(self, yaml_file: str) -> str:
		"""
		Method that converts the data stored in a YAML file into a string.

		Parameters:
			yaml_file (str): YAML file.

		Returns:
			data_str (str): String obtained from the conversion.
		"""
		try:
			with open(yaml_file, 'r') as file:
				data = safe_load(file) or {}
			def mask_sensitive_data(node):
				if isinstance(node, dict):
					return {k: ("*Encrypted Data*" if "token" in k.lower() or "password" in k.lower() or "key" in k.lower() or isinstance(v, bytes) else mask_sensitive_data(v)) for k, v in node.items()}
				elif isinstance(node, list):
					return [("*Encrypted Data*" if isinstance(item, bytes) else mask_sensitive_data(item)) for item in node]
				elif isinstance(node, bytes):
					return "*Encrypted Data*"
				return node
			masked_data = mask_sensitive_data(data)
			return safe_dump(masked_data, default_flow_style=False)
		except Exception as exception:
			raise IOError(f"Error converting YAML to string safely: {str(exception)}")


	def convert_yaml_to_txt(self, yaml_file: str, txt_file: str) -> None:
		"""
		Method that converts a YAML file into a TXT file.

		Parameters:
			yaml_file (str): YAML file's path.
			txt_file (str): TXT file's path.
		"""
		try:
			with open(yaml_file, 'r') as file:
				yaml_data = safe_load(file) or {}
			with open(txt_file, 'w') as file:
				for key, value in yaml_data.items():
					if isinstance(value, dict):
						for sub_key, sub_value in value.items():
							val_to_write = "*Encrypted*" if isinstance(sub_value, bytes) else sub_value
							file.write(f"{sub_key} - {val_to_write}\n")
					else:
						val_to_write = "*Encrypted*" if isinstance(value, bytes) else value
						file.write(f"{key} : {val_to_write}\n")
		except Exception as exception:
			raise IOError(f"Error exporting YAML to TXT: {str(exception)}")


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
		text = f"\n{title}\n"
		for item in list_to_convert:
			text += f"\n- {item}"
		return text


	def get_passphrase(self, key_file: str) -> str:
		"""
		Method that obtains the key to encrypt/decrypt data.

		Parameters:
			key_file (str): File where the key is stored.

		Returns:
			passphrase (str): Key to encrypt/decrypt data
		"""
		try:
			with open(key_file, 'r') as file:
				return file.read().strip()
		except Exception as exception:
			raise IOError(f"Critical: Failed to read key_file '{key_file}': {str(exception)}")


	def copy_file(self, source: str, destination: str) -> None:
		"""
		Method that copies a file.

		Parameters:
			source (str): Source file.
			destination (str): Destination folder.
		"""
		if path.exists(source):
			try:
				copy(source, destination)
			except Exception as exception:
				raise IOError(f"Failed to copy file from '{source}' to '{destination}': {str(exception)}")
		else:
			raise FileNotFoundError(f"Source file '{source}' does not exist.")


	def change_owner(self, path: str, user: str, group: str, mode: str) -> None:
		"""
		Method that changes the owner of a folder and/or file.
		
		Parameters:
			path (str): Folder and/or file.
			user (str): Owner user.
			group (str): Owner group.
			mode (str): New permissions.
		"""
		try:
			uid = getpwnam(user).pw_uid
			gid = getgrnam(group)[2]
			chown(path, uid, gid)
			chmod(path, int(mode, base = 8))
		except KeyError as ke:
			raise KeyError(f"System configuration error: User '{user}' or Group '{group}' does not exist on this OS. Details: {str(ke)}")
		except Exception as exception:
			raise OSError(f"Failed to apply ACL security permissions on '{path}': {str(exception)}")


	def validate_data_regex(self, data, regex) -> bool:
		"""
		Method that validates data using a regular expression.

		Parameters:
			data (int, str, double): Data to validate.
			regex (regular expression): Regular expression that validates the data.

		Returns:
			is_valid (bool): True if the data is valid, False otherwise.
		"""
		return bool(regex.match(str(data)))


	def validate_https_or_http(self, es_host: dict) -> bool:
		"""
		Method that validates whether the entered URL begins with HTTPS or not.

		Parameters:
			es_host (dict): Dictionary with the URLs to validate.

		Returns:
			(bool): True if URLs begin with HTTPS, false otherwise.
		"""
		if not es_host:
			return False
		return all(isinstance(host, str) and host.startswith("https://") for host in es_host)


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
			(f"{text} {i + 1}:", i + 1, 5, text, i + 1, 20, 30, 100) 
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

		Parameters:
			unit_time (str): Unit of time in which the total is expressed (minutes, hours or days).
			total_time (int): Total time to convert.

		Returns:
			total_seconds (int): Result of conversion to seconds.
		"""
		match unit_time:
			case "minutes":
				return total_time * 60
			case "hours":
				return total_time * 3600
			case "days":
				return total_time * 86400
			case _:
				return 0


	def get_gte_date(self, unit_time: str, total_time: int) -> str:
		"""
		Method that converts an amount of time expressed in minutes, hours or days into the gte value expressed in date math format.

		Parameters:
			unit_time (str): Unit of time in which the total is expressed (minutes, hours or days).
			total_time (int): Total time to convert.

		Returns:
			date_string (str): String in date math format.
		"""
		match unit_time:
			case "minutes":
				return f"now-{total_time}m/m"
			case "hours":
				return f"now-{total_time}h/h"
			case "days":
				return f"now-{total_time}d/d"
			case _:
				return "now"


	def get_lte_date(self, unit_time: str) -> str:
		"""
		Method that converts an amount of time expressed in minutes, hours or days into the lte value expressed in date math format.

		Parameters:
			unit_time (str): Unit of time in which the total is expressed (minutes, hours or days).

		Returns:
			date_string (str): String in date math format.
		"""
		match unit_time:
			case "minutes":
				return "now/m"
			case "hours":
				return "now/h"
			case "days":
				return "now/d"
			case _:
				return "now"


	def manage_daemon(self, daemon_name: str, option: int) -> int:
		"""
		Method that manages a daemon or service (start, restart, and stop).

		Parameters:
			daemon_name (str): Daemon's name.
			option (int): Option to perform (1.- Start daemon, 2.- Restart daemon, 3.- Stop daemon)

		Returns:
			result (int): Result of the command execution.
		"""
		action_map = {1: "start", 2: "restart", 3: "stop"}
		action = action_map.get(option)
		if not action:
			return -1
		try:
			result = subprocess.run(["systemctl", action, str(daemon_name)], capture_output = True, text = True, check = False)
			return result.returncode
		except Exception:
			return -1


	def get_detailed_status_by_daemon(self, daemon_name: str, file_name) -> str:
		"""
		Method that gets the current detailed status of a daemon.

		Parameters:
			daemon_name (str): Daemon's name.
			file_name (str): File where the detailed status of the daemon is saved.

		Returns:
			service_status (str): Detailed status of the service or daemon.
		"""
		try:
			is_active_res = subprocess.run(["systemctl", "is-active", "--quiet", str(daemon_name)], check = False)
			status_text = "Service is running!\n" if is_active_res.returncode == 0 else "Service is not running!\n"
			detailed_res = subprocess.run(["systemctl", "-l", "status", str(daemon_name)], capture_output = True, text = True, check = False)
			service_status = f"{status_text}Detailed service status:\n{detailed_res.stdout}"
			return service_status
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
		try:
			res = subprocess.run(["systemctl", "is-active", "--quiet", str(daemon_name)], check = False)
			return "Running" if res.returncode == 0 else "Not running"
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
		try:
			res = subprocess.run(["systemctl", "show", "--property", "MainPID", "--value", str(daemon_name)], capture_output = True, text = True, check = False)
			pid_str = res.stdout.strip()
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
		if pid <= 0:
			return 0
		try:
			process = Process(pid)
			return int(process.num_threads())
		except (NoSuchProcess, Exception):
			return 0


	def get_hash_from_file(self, file_path: str) -> str:
		"""
		Method that obtains the "sha256" hash of a file.

		Parameters:
			file_path (str): File path.

		Returns:
			(str): File hash.
		"""
		hash_sha256 = sha256()
		try:
			with open(file_path, "rb") as file:
				for block in iter(lambda: file.read(4096), b""):
					hash_sha256.update(block)
			return hash_sha256.hexdigest()
		except Exception as exception:
			raise IOError(f"Failed to calculate file hash: {str(exception)}")


	def encrypt_data(self, data: str, passphrase: str) -> tuple:
		"""
		Method that encrypts data using the AES-GCM algorithm.

		Parameters:
			data (str): Data to be encrypted.
			passphrase (str): Key to encrypt data.

		Returns:
			A tuple with the encrypted data.
		"""
		try:
			data_in_bytes = bytes(data, "utf-8")
			key = sha256(passphrase.encode()).digest()
			aes = AES.new(key, AES.MODE_GCM)
			encrypt_data, auth_tag = aes.encrypt_and_digest(data_in_bytes)
			return (encrypt_data, aes.nonce, auth_tag)
		except Exception as exception:
			raise ValueError(f"Encryption process failed: {str(exception)}")


	def decrypt_data(self, data: tuple, passphrase: str) -> str:
		"""
		Method that decrypts data using the AES-GCM algorithm.

		Parameters:
			data (tuple): Data to be decrypted.
			passphrase (str): Key to decrypt data.

		Returns:
			decrypt_data (str): Decrypted data.
		"""
		try:
			(encrypt_data, nonce, auth_tag) = data
			key = sha256(passphrase.encode()).digest()
			aes = AES.new(key, AES.MODE_GCM, nonce)
			decrypt_data = aes.decrypt_and_verify(encrypt_data, auth_tag)
			return decrypt_data.decode("utf-8")
		except Exception as exception:
			raise ValueError(f"Decryption / Authentication check failed (Possible key tampering): {str(exception)}")
		