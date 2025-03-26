"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyUtils
libPyUtils v2.2 - March 2025
"""
from glob import glob
from shutil import copy
from pwd import getpwnam
from grp import getgrnam
from hashlib import sha256
from os import chown, chmod, path
from Cryptodome.Cipher import AES
from dataclasses import dataclass
from yaml import safe_load, safe_dump

@dataclass
class libPyUtils:
	"""
	Utilities for easy creation of Python applications.
	"""

	def create_yaml_file(self, data: dict, yaml_file: str) -> None:
		"""
		Method that creates a YAML file.

		Parameters:
			data (dict): Data to save in the file.
			yaml_file (str): YAML file.
		"""
		with open(yaml_file, 'w') as file:
			safe_dump(data, file, default_flow_style = False)


	def read_yaml_file(self, yaml_file: str) -> dict:
		"""
		Method that reads and obtains the data stored in a YAML file.

		Parameters:
			yaml_file (str): YAML file.

		Returns:
			data (dict): Data saved to file.
		"""
		with open(yaml_file, 'r') as file:
			data = safe_load(file)
		return data


	def get_yaml_files_in_folder(self, folder_path: str) -> list:
		"""
		Method that obtains the names of YAML files stored in a specific path.

		Parameters:
			folder_path (str): Path where the YAML files will be listed.

		Returns:
			yaml_files (list): List with the names of the YAML files.
		"""
		yaml_files = [path.basename(yaml_file) for yaml_file in glob(f"{folder_path}/*.yaml")]
		return yaml_files


	def convert_yaml_to_str(self, yaml_file: str) -> str:
		"""
		Method that converts the data stored in a YAML file into a string.

		Parameters:
			yaml_file (str): YAML file.

		Returns:
			data_str (str): String obtained from the conversion.
		"""
		with open(yaml_file, 'r') as file:
			data = safe_load(file)
		for key in data:
			if type(data[key]) == list:
				for item in data[key]:
					if type(item) == bytes:
						data[key] = "Encrypted data"
		data_str = safe_dump(data, default_flow_style = False)
		return data_str


	def get_str_from_list(self, list_to_convert: list, title: str) -> str:
		"""
		Method converts a list in a string.

		Parameters:
			list_to_convert (list): List to convert.
			title (str): Title displayed.

		Returns:
			text (str): String obtained from the conversion.
		"""
		text = '\n' + title + '\n'
		for item in list_to_convert:
			text += "\n- " + item
		return text


	def get_passphrase(self, key_file: str) -> str:
		"""
		Method that obtains the key to encrypt/decrypt data.

		Parameters:
			key_file (str): File where the key is stored.

		Returns:
			passphrase (str): Key to encrypt/decrypt data
		"""
		file = open(key_file, 'r')
		passphrase = file.read()
		file.close()
		return passphrase


	def copy_file(self, source: str, destination: str) -> None:
		"""
		Method that copies a file.

		Parameters:
			source (str): Source file.
			destination (str): Destination folder.
		"""
		copy(source, destination) if path.exists(source) else print("Error") 


	def change_owner(self, path: str, user: str, group: str, mode: str) -> None:
		"""
		Method that changes the owner of a folder and/or file.
		
		Parameters:
			path (str): Folder and/or file.
			user (str): Owner user.
			group (str): Owner group.
			mode (str): New permissions.
		"""
		uid = getpwnam(user).pw_uid
		gid = getgrnam(group)[2]
		chown(path, uid, gid)
		chmod(path, int(mode, base = 8))


	def validate_data_regex(self, data, regex) -> bool:
		"""
		Method that validates data using a regular expression.

		Parameters:
			data (int, str, double): Data to validate.
			regex (regular expression): Regular expression that validates the data.

		Returns:
			is_valid (bool): True if the data is valid, False otherwise.
		"""
		is_valid = False if not regex.match(data) else True
		return is_valid


	def validate_https_or_http(self, es_host: dict) -> bool:
		"""
		Method that validates whether the entered URL begins with HTTPS or not.

		Parameters:
			es_host (dict): Dictionary with the URLs to validate.

		Returns:
			(bool): True if URLs begin with HTTPS, false otherwise.
		"""
		cont = 0
		for host in es_host:
			if host.startswith("https://"):
				cont += 1
		if cont == len(es_host):
			return True
		return False


	def generate_tuple_to_form(self, tuple_length: int, text: str) -> tuple:
		"""
		Method that generates a tuple for a pythondialog form.

		Parameters:
			tuple_length (int): Tuple length.
			text (str): Text to be displayed.

		Returns:
			tuple_to_form (tuple): Tuple for pythondialog form.
		"""
		tuple_to_form = []
		[tuple_to_form.append((text + ' ' + str(i + 1) + ':', (i + 1), 5, text, (i + 1), 20, 30, 100)) for i in range(tuple_length)]
		return tuple_to_form


	def convert_list_to_tuple(self, list_to_convert: list, text : str) -> tuple:
		"""
		Method that converts a list into a tuple for a pythondialog form.

		Parameters:
			list_to_convert (list): List to convert.
			text (str): Text to be displayed.

		Returns:
			tuple_to_form (tuple): Tuple for pythondialog form.
		"""
		tuple_to_form = []
		[tuple_to_form.append((text + ' ' + str(i + 1) + ':', (i + 1), 5, item, (i + 1), 20, 30, 100)) for i, item in enumerate(list_to_convert)]
		return tuple_to_form


	def convert_list_to_tuple_rc(self, list_to_convert: list, text: str) -> tuple:
		"""
		Method that converts a list into a tuple for a pythondialog radiolist or pythondialog checklist.

		Parameters:
			list_to_convert (list): List to convert.
			text (str): Text to be displayed.

		Returns:
			tuple_to_rc (tuple): Tuple for pythondialog radiolist or pythondialog checklist.
		"""
		tuple_to_rc = []
		[tuple_to_rc.append((item, text, 0)) for item in list_to_convert]
		return tuple_to_rc


	def get_hash_from_file(self, file_path: str) -> str:
		"""
		Method that obtains the "sha256" hash of a file.

		Parameters:
			file_path (str): File path.

		Returns:
			(str): File hash.
		"""
		hash_sha256 = sha256()
		with open(file_path, "rb") as file:
			for block in iter(lambda: file.read(4096), b""):
				hash_sha256.update(block)
		return hash_sha256.hexdigest()


	def encrypt_data(self, data: str, passphrase: str) -> tuple:
		"""
		Method that encrypts data using the AES-GCM algorithm.

		Parameters:
			data (str): Data to be encrypted.
			passphrase (str): Key to encrypt data.

		Returns:
			A tuple with the encrypted data.
		"""
		data_in_bytes = bytes(data, "utf-8")
		key = sha256(passphrase.encode()).digest()
		aes = AES.new(key, AES.MODE_GCM)
		encrypt_data, auth_tag = aes.encrypt_and_digest(data_in_bytes)
		return (encrypt_data, aes.nonce, auth_tag)


	def decrypt_data(self, data: tuple, passphrase: str) -> str:
		"""
		Method that decrypts data using the AES-GCM algorithm.

		Parameters:
			data (tuple): Data to be decrypted.
			passphrase (str): Key to decrypt data.

		Returns:
			decrypt_data (str): Decrypted data.
		"""
		(encrypt_data, nonce, auth_tag) = data
		key = sha256(passphrase.encode()).digest()
		aes = AES.new(key, AES.MODE_GCM, nonce)
		decrypt_data = aes.decrypt_and_verify(encrypt_data, auth_tag)
		return decrypt_data