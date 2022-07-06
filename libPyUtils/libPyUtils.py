from glob import glob
from pwd import getpwnam
from Crypto import Random
from hashlib import sha256
from tabulate import tabulate
from Crypto.Cipher import AES
from shutil import rmtree, copy
from yaml import safe_load, safe_dump
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from os import chown, mkdir, path, scandir, rename, remove

class libPyUtils:

	def createYamlFile(self, data, path_file_yaml):
		"""
		Method that creates a YAML file.

		:arg data (JSON): Data that will be stored in the YAML file.
		:arg path_file_yaml (string): Absolute path where the YAML file will be created.
		"""
		with open(path_file_yaml, 'w') as file_yaml:
			safe_dump(data, file_yaml, default_flow_style = False)


	def readYamlFile(self, path_file_yaml):
		"""
		Method that reads a YAML file.

		Returns the data from the YAML file.

		:arg path_file_yaml (string): Absolute path where the YAML file will be readed.
		"""
		with open(path_file_yaml, 'r') as file_yaml:
			data_file_yaml = safe_load(file_yaml)
		return data_file_yaml


	def convertDataYamlFileToString(self, path_file_yaml):
		"""
		Method that converts a YAML file in a string.

		Returns the string with the YAML file data.

		:arg path_file_yaml (string): Absolute path where the YAML file will be readed.
		"""
		with open(path_file_yaml, 'r') as file_yaml:
			data_file_yaml = safe_load(file_yaml)
		data_file_yaml = safe_dump(data_file_yaml,  default_flow_style = False)
		return data_file_yaml


	def copyFile(self, path_original_file, path_copy_file):
		"""
		Method that copies a file.

		:arg path_original_file (string): Absolute path of the original file.
		:arg path_copy_file (string): Absolute path where the original file will be copied.
		"""
		if path.exists(path_original_file):
			copy(path_original_file, path_copy_file)


	def createNewFolder(self, path_new_folder):
		"""
		Method that creates a new folder or directory.

		:arg path_new_folder (string): Absolute path of the new folder.
		"""
		if not path.isdir(path_new_folder):
			mkdir(path_new_folder)

	
	def renameFileOrFolder(self, path_to_rename, new_path_name):
		"""
		Method that renames a file or directory.

		:arg path_to_rename (string): Absolute path of the element to rename.
		:arg new_path_name (string): Absolute path with the new element name.
		"""
		if path.exists(path_to_rename):
			rename(path_to_rename, new_path_name)


	def deleteFile(self, path_file_to_delete):
		"""
		Method that removes a specific file.

		:arg path_file_to_delete (string): Absolute path of the file to be removed.
		"""
		if path.exists(path_file_to_delete):
			remove(path_file_to_delete)


	def deleteFolder(self, path_folder_to_delete):
		"""
		Method that removes an entire directory with all the elements inside it.

		:arg path_folder_to_delete (string): Absolute path of the directory to be removed.
		"""
		if path.exists(path_folder_to_delete):
			rmtree(path_folder_to_delete)


	def createFileWithTable(self, path_table_file, data_table, headers_table):
		"""
		Method that creates a file with a data table using tabulate.

		:arg path_table_file (string): Absolute path of the file that will be created. 
		:arg data_table (list): List with the data to form the table.
		:arg headers_table (list): List with the headers to form the table. 
		"""
		with open(path_table_file, 'w') as table_file:
			table_file.write(tabulate(data_table, headers_table, tablefmt = "grid"))


	def validateDataWithRegularExpression(self, regular_expression, data):
		"""
		Method that validates data entered by means of a regular expression.

		Return True if the data matches the regular expression. False otherwise.

		:arg regular_expression (string): Regular expression that will be used to validate the data.
		:arg data (string): Data that will be validated.
		"""
		if(not regular_expression.match(data)):
			return False
		return True


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


	def createListToDialogForm(self, len_to_list, text_to_show):
		"""
		Method that converts a list into a list that can be used in a RadioList or CheckList dialog.

		Return the list for a form dialog.

		:arg list_to_convert (list): List to convert.
		:arg text_to_show (string): Text that will be displayed next to the option in the dialog.
		"""
		list_to_form_dialog = []
		for i in range(len_to_list):
			list_to_form_dialog.append((text_to_show + ' ' + str(i + 1) + ':', (i + 1), 5, text_to_show, (i +1), 20, 30, 100))
		return list_to_form_dialog


	def convertListToDialogForm(self, list_to_convert, text_to_show):
		"""
		Method that converts a list into a list that can be used in a Form dialog.

		Return the converted list for a Form dialog.

		:arg list_to_convert (list): List to convert.
		:arg text_to_show (string): Text that will be displayed next to the option in the dialog.
		"""
		i = 0
		list_to_form_dialog = []
		for item in list_to_convert:
			list_to_form_dialog.append((text_to_show + ' ' + str(i + 1) + ':', (i + 1), 5, item, (i +1), 20, 30, 100))
			i += 1
		return list_to_form_dialog


	def convertListToDialogList(self, list_to_convert, text_to_show):
		"""
		Method that converts a list into a list that can be used in a RadioList or CheckList dialog.

		Return the converted list for a checklist or radiolist dialog.

		:arg list_to_convert (list): List to convert.
		:arg text_to_show (string): Text that will be displayed next to the option in the dialog.
		"""
		list_to_dialog = []
		for item in list_to_convert:
			list_to_dialog.append((item, text_to_show, 0))
		return list_to_dialog


	def getPassphraseKeyFile(self, path_key_file):
		"""
		Method that reads the passphrase from the key file.

		Return the passphrase in a string.

		:arg path_key_file (string): Absolute path of the key file.
		"""
		key_file = open(path_key_file,'r')
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


	def getListOfAllYamlFilesInFolder(self, folder_path):
		"""
		Method that gets all YAML files in a specific folder

		Return all YAML files found in the folder (names)

		:arg folder_path (string): Absolute folder path
		"""
		list_all_files_yaml = [path.basename(x) for x in glob(folder_path + '/*.yaml')]
		return list_all_files_yaml


	def changeOwnerToPath(self, path_to_change, user, group):
		"""
		Method that changes the user and group ownership of a directory or file.

		:arg path_to_change (string): Absolute path of the directory or file to change ownership.
		:arg user (string): New owner user.
		:arg group (string): New owner group.
		"""
		uid = getpwnam(user).pw_uid
		gid = getpwnam(group).pw_gid
		chown(path_to_change, uid, gid)


	def getHashFunctionToFile(self, path_file):
		"""
		Method that obtains the hash (sha256) of a file.
		
		Returns the hash of the file.

		:arg path_file (string): Absolute path of the file.
		"""
		hash_sha = sha256()
		with open(path_file, 'rb') as file_to_hash:
			for block in iter(lambda: file_to_hash.read(4096), b""):
				hash_sha.update(block)
		return hash_sha.hexdigest()


	def encryptDataWithAES(self, data_to_encrypt, passphrase):
		"""
		Method that encrypts data using the AES algorithm.
		
		Returns the encrypted data.

		:arg data_to_encrypt (string): Date to be encrypted.
		:arg passphrase (string): Passphrase used for the encryption/decryption process.
		"""
		text_bytes = bytes(data_to_encrypt, 'utf-8')
		key = sha256(passphrase.encode()).digest()
		IV = Random.new().read(AES.block_size)
		aes = AES.new(key, AES.MODE_CBC, IV)
		return b64encode(IV + aes.encrypt(pad(text_bytes, AES.block_size)))


	def decryptDataWithAES(self, data_to_decrypt, passphrase):
		"""
		Method that decrypts data using the AES algorithm.
		
		Returns the decrypted data.

		:arg data_to_encrypt (string): Date to be decrypted.
		:arg passphrase (string): Passphrase used for the encryption/decryption process.
		"""
		key = sha256(passphrase.encode()).digest()
		data_to_decrypt = b64decode(data_to_decrypt)
		IV = data_to_decrypt[:AES.block_size]
		aes = AES.new(key, AES.MODE_CBC, IV)
		return unpad(aes.decrypt(data_to_decrypt[AES.block_size:]), AES.block_size)