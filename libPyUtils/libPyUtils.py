"""
Author: Erick Roberto Rodriguez Rodriguez
Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com
GitHub: https://github.com/erickrr-bd/libPyUtils
libPyUtils v2.1 - October 2024
"""
from shutil import copy
from pwd import getpwnam
from grp import getgrnam
from hashlib import sha256
from os import chown, chmod, path
from Cryptodome.Cipher import AES
from yaml import safe_load, safe_dump

class libPyUtils:

	def create_yaml_file(self, data, yaml_file):
		"""
		Method that creates a YAML file.

		:arg data (JSON): Dictionary with data.
		:arg yaml_file (String): YAML file.
		"""
		with open(yaml_file, 'w') as file:
			safe_dump(data, file, default_flow_style = False)


	def read_yaml_file(self, yaml_file):
		"""
		Method that reads a YAML file.

		Returns a dictionary with the data from the YAML file.

		:arg yaml_file (String): YAML file.
		"""
		with open(yaml_file, 'r') as file:
			data = safe_load(file)
		return data


	def convert_yaml_data_to_string(self, yaml_file):
		"""
		Method that converts the data of a YAML file into a string.

		Returns a string with the data of the YAML file.

		:arg yaml_file (String): YAML file.
		"""
		with open(yaml_file, 'r') as file:
			data = safe_load(file)
		for key in data:
			if type(data[key]) == list:
				for item in data[key]:
					if type(item) == bytes:
						data[key] = "Encrypted data"
		data_string = safe_dump(data, default_flow_style = False)
		return data_string


	def get_string_from_list(self, list_to_convert, title):
		"""
		Method converts a list in a string.

		Returns a string.

		:arg list_to_convert (List): List to convert.
		:arg title (String): Title displayed.
		"""
		text = '\n' + title + '\n'
		for item in list_to_convert:
			text += "\n- " + item
		return text


	def get_passphrase(self, key_file):
		"""
		Method that obtains the key to encrypt/decrypt data from a file.

		Returns a string with the key.

		:arg key_file (String): File where the key is stored.
		"""
		file = open(key_file, 'r')
		passphrase = file.read()
		file.close()
		return passphrase


	def copy_file(self, source, destination):
		"""
		Method that copies a file.
		
		:arg source (String): Source file.
		:arg destination (String): Destination folder.
		"""
		copy(source, destination) if path.exists(source) else print("Error") 


	def change_owner(self, path, user, group, mode):
		"""
		Method that changes the owner of a directory and/or file.

		:arg path (String): Directory and/or file path.
		:arg user (String): Owner user.
		:arg group (String): Owner group.
		:arg mode (String): New permissions.
		"""
		uid = getpwnam(user).pw_uid
		gid = getgrnam(group)[2]
		chown(path, uid, gid)
		chmod(path, int(mode, base = 8))


	def validate_data_regex(self, data, regex):
		"""
		Method that validates data using a regular expression.

		Returns a boolean value (True or False).

		:arg data (Integer, String, Double): Data to validate.
		:arg regex (Rgular Expression): Regular expression to use.
		"""
		is_valid = False if not regex.match(data) else True
		return is_valid


	def generate_tuple_to_form(self, tuple_length, text):
		"""
		Method that generates a tuple for a form.

		Returns a tuple.

		:arg tuple_length (Integer): List length.
		:arg text (String): Text to be displayed.
		"""
		tuple_to_form = []
		[tuple_to_form.append((text + ' ' + str(i + 1) + ':', (i + 1), 5, text, (i + 1), 20, 30, 100)) for i in range(tuple_length)]
		return tuple_to_form


	def convert_list_to_tuple(self, list_to_convert, text):
		"""
		Method that converts a list into a tuple for a form.

		Return a tuple.

		:arg list_to_convert (List): List to convert to tuple.
		:arg text (String): Text to be displayed.
		"""
		tuple_to_form = []
		[tuple_to_form.append((text + ' ' + str(i + 1) + ':', (i + 1), 5, item, (i + 1), 20, 30, 100)) for i, item in enumerate(list_to_convert)]
		return tuple_to_form


	def convert_list_to_tuple_rc(self, list_to_convert, text):
		"""
		Method that converts a list into a tuple for a radiolist or checklist.

		Return a tuple.

		arg list_to_convert (List): List to convert to tuple.
		:arg text (String): Text to be displayed.
		"""
		tuple_to_rc = []
		[tuple_to_rc.append((item, text, 0)) for item in list_to_convert]
		return tuple_to_rc


	def get_hash_from_file(self, file_path):
		"""
		Method that obtains the sha256 hash of a file.
		
		Returns a string with the hash of the file.

		:arg file_path (String): File path.
		"""
		hash_sha256 = sha256()
		with open(file_path, "rb") as file:
			for block in iter(lambda: file.read(4096), b""):
				hash_sha256.update(block)
		return hash_sha256.hexdigest()


	def encrypt_data(self, data, passphrase):
		"""
		Method that encrypts data using the AES-GCM algorithm.

		Returns a tuple with the encrypted data.

		:arg data (String): Data to be encrypted.
		:arg passphrase (String): Key to encrypt data.
		"""
		data_in_bytes = bytes(data, "utf-8")
		key = sha256(passphrase.encode()).digest()
		aes = AES.new(key, AES.MODE_GCM)
		encrypt_data, auth_tag = aes.encrypt_and_digest(data_in_bytes)
		return (encrypt_data, aes.nonce, auth_tag)


	def decrypt_data(self, data, passphrase):
		"""
		Method that decrypts data using the AES-GCM algorithm.

		Returns a string with the decrypted data.

		:arg data (Tuple): Data to be decrypted.
		:arg passphrase (String): Key to decrypt data.
		"""
		(encrypt_data, nonce, auth_tag) = data
		key = sha256(passphrase.encode()).digest()
		aes = AES.new(key, AES.MODE_GCM, nonce)
		decrypt_data = aes.decrypt_and_verify(encrypt_data, auth_tag)
		return decrypt_data