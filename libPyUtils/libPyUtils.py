from glob import glob
from pwd import getpwnam
from hashlib import sha256
from binascii import hexlify
from shutil import rmtree, copy
from Cryptodome.Cipher import AES
from yaml import safe_load, safe_dump
from os import chown, mkdir, path, scandir, rename, remove, chmod

class libPyUtils:

	def createYamlFile(self, json_data, yaml_file_path):
		"""
		Method that creates a YAML file.

		:arg json_data (dict): Dictionary with the data to be stored in the file.
		:arg yaml_file_path (string): Absolute path of the YAML file.
		"""
		with open(yaml_file_path, 'w') as yaml_file:
			safe_dump(json_data, yaml_file, default_flow_style = False)


	def readYamlFile(self, yaml_file_path):
		"""
		Method that reads a YAML file.

		Returns a dictionary with the data stored in the YAML file.

		:arg path_yaml_file (string): Absolute path of the YAML file.
		"""
		with open(yaml_file_path, 'r') as yaml_file:
			yaml_file_data = safe_load(yaml_file)
		return yaml_file_data


	def convertYamlFileToString(self, yaml_file_path):
		"""
		Method that converts the content of a YAML file to a string.

		Returns the string formed from the content of the YAML file.

		:arg yaml_file_path (string): Absolute path of the YAML file.
		"""
		with open(yaml_file_path, 'r') as yaml_file:
			yaml_file_data = safe_load(yaml_file)
		for key in yaml_file_data:
			if type(yaml_file_data[key]) == list:
				for item in yaml_file_data[key]:
					if type(item) == bytes:
						yaml_file_data[key] = "Encrypted value"
		yaml_file_data = safe_dump(yaml_file_data,  default_flow_style = False)
		return yaml_file_data


	def copyFile(self, source_file_path, destination_file_path):
		"""
		Method that copies a file to a new destination.

		:arg source_file_path (string): Absolute path of the file.
		:arg destination_file_path (string): Absolute path of the destination of the file.
		"""
		copy(source_file_path, destination_file_path) if path.exists(source_file_path) else False


	def createFolder(self, folder_path):
		"""
		Method that creates a folder.

		:arg folder_path (string): Absolute path of the folder.
		"""
		mkdir(folder_path) if not path.isdir(folder_path) else False

	
	def renameFileOrFolder(self, file_folder_original, file_folder_new):
		"""
		Method that renames a file or folder.

		:arg file_folder_original (string): Absolute path of the file or folder to rename.
		:arg file_folder_new (string): Absolute path with the new name of the file or folder.
		"""
		rename(file_folder_original, file_folder_new) if path.exists(file_folder_original) else False


	def deleteFile(self, file_path):
		"""
		Method that deletes a file.

		:arg file_path (string): Absolute path of the file.
		"""
		remove(file_path) if path.exists(file_path) else False


	def deleteFolder(self, folder_path):
		"""
		Method that deletes a directory (and the files inside it if they exist).

		:arg folder_path (string): Absolute path of the folder.
		"""
		rmtree(folder_path) if path.exists(folder_path) else False


	def validateDataRegex(self, regex, data):
		"""
		Method that validates data based on a regular expression.

		Returns a boolean value, where it will be true if the data is valid, otherwise it will be false.

		:arg regex (string): Regular expression.
		:arg data (string): Data that will be validated based on the regular expression.
		"""
		is_data_valid = False if not regex.match(data) else True
		return is_data_valid


	def convertTimeToSeconds(self, unit_time, total_time):
		"""
		Method that converts an amount of time expressed in a unit of time into seconds.

		Returns the total seconds.

		:arg unit_time (string): Unit of time in which the quantity is expressed.
		:arg total_time (integer): Amount of time to convert.
		"""
		if unit_time == "minutes":
			total_seconds = total_time * 60
		elif unit_time == "hours":
			total_seconds = total_time * 3600
		elif unit_time == "days":
			total_seconds = total_time * 86400
		return total_seconds


	def getGteDateMathElasticSearch(self, unit_time, total_time):
		"""
		Method that generates the gte value in date math format.
		
		Returns the date math string formed.

		:arg unit_time (string): Unit of time in which the quantity is expressed.
		:arg total_time (integer): Amount of time to convert.
		"""
		date_math_string = "now-"
		if unit_time == "minutes":
			date_math_string += str(total_time) + 'm/m'
		elif unit_time == "hours":
			date_math_string += str(total_time) + 'h/h'
		elif unit_time == "days":
			date_math_string += str(total_time) + 'd/d'
		return date_math_string


	def getLteDateMathElasticSearch(self, unit_time):
		"""
		Method that generates the lte value in date math format.
		
		Returns the date math string formed.

		:arg unit_time (string): Unit of time in which the quantity is expressed.
		"""
		date_math_string = ""
		if unit_time == "minutes":
			date_math_string += "now/m"
		elif unit_time == "hours":
			date_math_string += "now/h"
		elif unit_time == "days":
			date_math_string += "now/d"
		return date_math_string


	def createListToDialogForm(self, list_len, text):
		"""
		Method that creates a formatted list for a form.

		Returns the created list.

		:arg list_len (integer): List length.
		:arg text (string): Text to be displayed on the form.
		"""
		list_form = []
		[list_form.append((text + ' ' + str(i + 1) + ':', (i + 1), 5, text, (i +1), 20, 30, 100)) for i in range(list_len)]
		return list_form


	def convertListToDialogForm(self, list_to_convert, text):
		"""
		Method that converts a list to a list for a form.

		Returns the converted list.

		:arg list_to_convert (list): List to convert.
		:arg text (string): Text to be displayed on the form.
		"""
		list_form = []
		[list_form.append((text + ' ' + str(i + 1) + ':', (i + 1), 5, item, (i +1), 20, 30, 100)) for i, item in enumerate(list_to_convert)]
		return list_form


	def convertListToDialogList(self, list_to_convert, text):
		"""
		Method that converts a list to a list for a Checklist or RadioList Dialog.

		Returns the converted list.

		:arg list_to_convert (list): List to convert.
		:arg text (string): Text to be displayed on the Checklist or Radiolist dialog.
		"""
		list_checklist_radiolist = []
		[list_checklist_radiolist.append((item, text, 0)) for item in list_to_convert]
		return list_checklist_radiolist


	def getStringFromList(self, list_to_convert, title):
		"""
		Method converts a list in a string.

		Returns the converted string.

		:arg list_to_convert (list): List to convert.
		:arg title (string): Title displayed.
		"""
		message_to_display = '\n' + title + '\n'
		for item in list_to_convert:
			message_to_display += "\n- " + item
		return message_to_display


	def getPassphraseKeyFromFile(self, key_file_path):
		"""
		Method that obtains the encryption key of a file.

		Returns a string with the encryption key.

		:arg key_file_path (string): Absolute path of the file.
		"""
		key_file = open(key_file_path,'r')
		passphrase = key_file.read()
		key_file.close()
		return passphrase


	def getListToAllSubDirectories(self, parent_directory_path):
		"""
		Method that gets all subdirectories of a parent directory.

		Return all found subdirectories.
	
		:arg parent_directory_path (string): Home directory path.
		"""
		with scandir(parent_directory_path) as directories:
			sub_directories = [directory.name for directory in directories if directory.is_dir()]
		return sub_directories


	def getListYamlFilesInFolder(self, folder_path):
		"""
		Method that obtains a list with the names of the YAML files inside a folder.

		Returns a list with the names of the YAML files.

		:arg folder_path (string): Absolute path of the folder.
		"""
		files_yaml_list = [path.basename(x) for x in glob(folder_path + '/*.yaml')]
		return files_yaml_list


	def changeFileFolderOwner(self, file_folder_path, user, group, mode):
		"""
		Method that changes the owner of a file or folder.

		:arg file_folder_path (string): Absolute path of the file or folder.
		:arg user (string): Username.
		:arg group (string): Group name.
		:arg mode (string): Mode expressed as an integer.
		"""
		uid = getpwnam(user).pw_uid
		gid = getpwnam(group).pw_gid
		chown(file_folder_path, uid, gid)
		chmod(file_folder_path, int(mode, base = 8))


	def getHashFunctionOfFile(self, file_path):
		"""
		Method that obtains the hash (sha256) of a file.
		
		Returns the hash of the file.

		:arg file_path (string): AAbsolute path of the file.
		"""
		hash_sha256 = sha256()
		with open(file_path, "rb") as file:
			for block in iter(lambda: file.read(4096), b""):
				hash_sha256.update(block)
		return hash_sha256.hexdigest()


	def encryptDataWithAES(self, data_to_encrypt, passphrase):
		"""
		Method that encrypted data using the AES algorithm in GCM mode.
		
		Returns a list with the encryption data.

		:arg data_to_encrypt (string): Date to encrypt.
		:arg passphrase (string): Passphrase used for the encryption/decryption process.
		"""
		data_in_bytes = bytes(data_to_encrypt, "utf-8")
		key = sha256(passphrase.encode()).digest()
		aes = AES.new(key, AES.MODE_GCM)
		encrypt_data, auth_tag = aes.encrypt_and_digest(data_in_bytes)
		return (encrypt_data, aes.nonce, auth_tag)


	def decryptDataWithAES(self, data_to_decrypt, passphrase):
		"""
		Method that decrypted data using the AES algorithm in GCM mode.
		
		Returns a string with the original value.

		:arg data_to_decrypt (list): Date to decrypt.
		:arg passphrase (string): Passphrase used for the encryption/decryption process.
		"""
		(encrypt_data, nonce, auth_tag) = data_to_decrypt
		key = sha256(passphrase.encode()).digest()
		aes = AES.new(key, AES.MODE_GCM, nonce)
		decrypt_data = aes.decrypt_and_verify(encrypt_data, auth_tag)
		return decrypt_data