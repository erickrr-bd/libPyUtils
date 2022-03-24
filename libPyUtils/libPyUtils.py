from os import chown
from pwd import getpwnam
from Crypto import Random
from hashlib import sha256
from Crypto.Cipher import AES
from yaml import safe_load, safe_dump
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad

class libPyUtils:

	def createYamlFile(self, data, path_file_yaml):
		"""
		Method that creates a YAML file.

		:arg data: Data that will be stored in the YAML file.
		:arg path_file_yaml: Absolute path where the YAML file will be created.
		"""
		with open(path_file_yaml, 'w') as file_yaml:
			safe_dump(data, file_yaml, default_flow_style = False)


	def readYamlFile(self, path_file_yaml):
		"""
		Method that reads a YAML file.

		Returns the data from the YAML file.

		:arg path_file_yaml: Absolute path where the YAML file will be readed.
		"""
		with open(path_file_yaml, 'r') as file_yaml:
			data_file_yaml = safe_load(file_yaml)
		return data_file_yaml


	def validateDataWithRegularExpression(self, regular_expression, data):
		"""
		Method that validates data entered by means of a regular expression.

		Return True if the data matches the regular expression. False otherwise.

		:arg regular_expression: Regular expression that will be used to validate the data.
		:arg data: Data that will be validated.
		"""
		if(not regular_expression.match(data)):
			return False
		return True


	def convertTimeToSeconds(self, unit_time, total_time):
		"""
		Method that converts an amount of time expressed in a unit of time into seconds.

		:arg unit_time: Unit of time in which the quantity is expressed.
		:arg total_time: Amount of time to convert.
		"""
		if unit_time == "minutes":
			total_seconds = total_time * 60
		elif unit_time == "hours":
			total_seconds = total_time * 3600
		elif unit_time == "days":
			total_seconds = total_time * 86400
		return total_seconds


	def convertTimeToStringSearch(self, unit_time, total_time):
		"""
		Method that converts an amount of time expressed in a unit of time into a string to perform searches in ElasticSearch.
		
		:arg unit_time: Unit of time in which the quantity is expressed.
		:arg total_time: Amount of time to convert.
		"""
		string_search = "now-"
		if unit_time == "minutes":
			string_search += str(total_time) + 'm'
		elif unit_time == "hours":
			string_search += str(total_time) + 'h'
		elif unit_time == "days":
			string_search += str(total_time) + 'd'
		return string_search


	def getPassphraseKeyFile(self, path_key_file):
		"""
		Method that reads the passphrase from the key file.

		Return the passphrase in a string.

		:arg path_key_file: Absolute path of the key file.
		"""
		key_file = open(path_key_file,'r')
		passphrase = key_file.read()
		key_file.close()
		return passphrase


	def changeOwnerToPath(self, path_to_change, user, group):
		"""
		Method that changes the user and group ownership of a directory or file.

		:arg path_to_change: Absolute path of the directory or file to change ownership.
		:arg user: New owner user.
		:arg group: New owner group.
		"""
		uid = getpwnam(user).pw_uid
		gid = getpwnam(group).pw_gid
		chown(path_to_change, uid, gid)


	def getHashFunctionToFile(self, path_file):
		"""
		Method that obtains the hash (sha256) of a file.
		
		Returns the hash of the file.

		:arg path_file: Absolute path of the file.
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

		:arg data_to_encrypt: Date to be encrypted.
		:arg passphrase: Passphrase used for the encryption/decryption process.
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

		:arg data_to_encrypt: Date to be decrypted.
		:arg passphrase: Passphrase used for the encryption/decryption process.
		"""
		key = sha256(passphrase.encode()).digest()
		data_to_decrypt = b64decode(data_to_decrypt)
		IV = data_to_decrypt[:AES.block_size]
		aes = AES.new(key, AES.MODE_CBC, IV)
		return unpad(aes.decrypt(data_to_decrypt[AES.block_size:]), AES.block_size)