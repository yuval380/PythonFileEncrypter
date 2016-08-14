from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import argparse
import os

class AES_Encrypter():
	def __init__(self, key):
		self.key = key
	
	def encrypt(self, data):
		HKEY = SHA256.new(self.key.encode('utf-8')).digest()
		IV = Random.new().read(AES.block_size)
		return IV + AES.new(HKEY, AES.MODE_CFB, IV).encrypt(data)

	def decrypt(self, encData):
		HKEY = SHA256.new(self.key.encode('utf-8')).digest()
		IV = encData[:AES.block_size]
		encData = encData[AES.block_size:]
		return AES.new(HKEY, AES.MODE_CFB, IV).decrypt(encData)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('file', type = str, help = "The file you want to encrypt/decrypt")
	parser.add_argument('password', type = str, help = "your password/key for encrypt/decrypt")
	parser.add_argument('-e', '--encrypt', action = 'store_true', help = "Encrypt the file, by default file will be decrypted")
	arguments = vars(parser.parse_args())
	
	# creating encrypter
	encrypter = AES_Encrypter(arguments['password'])
	
	# Encrypting / Decrypting the file
	if arguments['encrypt']:
		encrypt_file(arguments, encrypter)
	else:
		decrypt_file(arguments, encrypter)

# File encryption
def encrypt_file(arguments, encrypter):
	if os.path.isfile(arguments['file']):
		# oppening the file and creating the new encrypted file with a ".aes" postfix
		f0 = open(arguments['file'], 'rb')
		f1 = open(arguments['file']+'.aes', 'wb+')
		try:
			# ????ing file to chunks
			file_length = {}
			file_length['bytes'] = os.stat(arguments['file']).st_size
			file_length['chuncks'] = (file_length['bytes'] - (file_length['bytes']%256))/256
			if file_length['bytes']%256 != 0:
				file_length['chuncks'] += 1
			
			# Main encrypting loop
			work_done = 0
			print("The file {} was opened. stating encryption...".format(arguments['file']))
			while work_done != file_length['chuncks']:
				print("{} chunkes were encryptrd, still there are {} chuncks to encrypt (out of {} chuncks)".format(work_done, file_length['chuncks']-work_done, file_length['chuncks']))
				chunck = f0.read(256)
				f1.write(encrypter.encrypt(chunck))
				work_done += 1
			print("All encryption done! {} chunks ({} bytes) were Encrypted".format(work_done, work_done*256))
			print("closing files...")
		finally:
			f0.close()
			f1.close()
	else:
		print("ERROR: The file {} Dosent Exist".format(arguments['file']))

# File decryption
def decrypt_file(arguments, encrypter):
	if os.path.isfile(arguments['file']):
		postfix = ".aes"
		postfixless_name = arguments['file'][:len(arguments['file'])-4]
		if not arguments['file'][len(arguments['file'])-4:] == '.aes':
			while True:
				print("The file you are trying to decrypt dont have '.aes' postfix")
				print("Do you still want to decript file? [y/n]")
				i = input()
				if i == "n":
					raise Exception
				elif i == "y":
					break
				else:
					print("unvalide answer...")
			postfixless_name = arguments['file']
		try:
			# oppening the encrypted file and creating the new unencrypted file
			f0 = open(arguments['file'], 'rb+')
			f1 = open(postfixless_name, 'wb+')
			
			# ????ing file to chunks
			file_length = {}
			file_length['bytes'] = os.stat(arguments['file']).st_size
			file_length['chuncks'] = (file_length['bytes'] - (file_length['bytes']%272))/272
			if file_length['bytes']%272 != 0:
				file_length['chuncks'] += 1
			
			file_length['bytes'] = int(file_length['bytes'])
			file_length['chuncks'] = int(file_length['bytes'])
			
			# Main decrypting loop
			work_done = 0
			print("The file {} was opened. stating decryption...".format(arguments['file']))
			while work_done != file_length['chuncks']:
				print("{} chunkes were decryptrd, still there are {} chuncks to decrypt (out of {} chuncks)".format(work_done, file_length['chuncks']-work_done, file_length['chuncks']))
				chunck = f0.read(272)
				f1.write(encrypter.decrypt(chunck))
				work_done += 1
			print("All decryption done! {} chunks ({} bytes) were decrypted".format(work_done, work_done*272))
			print("closing files...")
		finally:
			f0.close()
			f1.close()
	else:
		print("ERROR: The file {} Dosent Exist".format(arguments['file']))



if __name__ == '__main__':
	main()
