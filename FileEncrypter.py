from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import argparse
import os

class AES_Encrypter():
	def __init__(self, key):
		self.key = key
	
	def encrypt(self, data):
		HKEY = SHA256.new(self.key).digest()
		IV = Random.new().read(AES.block_size)
		return IV + AES.new(HKEY, AES.MODE_CFB, IV).encrypt(data)

	def decrypt(self, encData)
		HKEY = SHA256.new(self.key).digest()
		IV = encData[:AES.block_size]
		encData = encData[AES.block_size:]
		return AES.new(HKEY, AES.MODE_CFB, IV).decrypt(encData)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('file', type = str, help = "The file you want to encrypt/decrypt")
	parser.add_argument('password', type = str, help = "your password/key for encrypt/decrypt")
	parser.add_argument('-e', '--encrypt', action = 'store_true', help = "Encrypt the file, by default file will be decrypted")
	arguments = var(parser.parse_args())
	
	# creating encrypter
	encrypter = AES_Encrypter.new(arguments['password'])
	
	# Encrypting / Decrypting the file
	if arguments['encrypt']:
		encrypt_file(arguments, encrypter)
	else:
		# decrypt_file(arguments, encrypter)


# File encryption
def encrypt_file(arguments, encrypter):
	if os.path.isfile(arguments['file']):
		try:
			# oppening the file and creating the new encrypted file with a ".aes" postfix
			f0 = open(arguments['file'], rb)
			f1 = open(arguments['file']+'.aes', wb+)
			
			# ????ing file to chunks
			file_length['bytes'] = os.stat(argument['file']).st_size
			file_length['chuncks'] = (file_length['bytes'] - (file_length['bytes']%16))/16
			if file_length['bytes']%16 != 0:
				file_length['chuncks']++
			
			# Main encrypting loop
			work_done = 0
			while work_done != file_length['chunks']:
				print("The file {} was opened. stating encryption...".format(arguments['file']))
				print("{} chunkes were encryptrd, still there are {} chuncks to encrypt (out of {} chuncks)".format(work_done), file_length['chunks']-work_done, file_length['chuncks'])
				chunck = f0.read(16)
				if len(chunck) < 16:
					for i in range(16-len(chunck)):
						chunk += b'\x00'
				f1.write(encrypter.encrypt(chunk))
				work_done++
			print("All encryption done! {} chunks ({} bytes) were Encrypted".format(work_done, work_done*16))
			print("closing files...")
		finally:
			f0.close()
			f1.close()
	else:
		print("ERROR: The file {} Dosent Exist".format(arguments['file']))




if __name__ == '__main__':
	main()
