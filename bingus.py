
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

class Bingus(object):
	def __init__(self):
		self.private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
		self.public_key = self.private_key.public_key()
		self.pem = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
		self.bank_public_key = None
		self.cert = bytes(256)
		self.key_chain = {} #keep a log of all public keys in your cohort
		self.is_bank = 0
		self.hostname = ''
		

	def encrypt(self, data, ctx=None, extra=b''):
		assert self.bank_public_key != None
		if ctx == None:
			ctx = self.bank_public_key #set default context

		if type(data) != bytes:
			data_bytes = data.encode('ascii')
		else:
			data_bytes = data

		timestamp = str(datetime.utcnow()).encode('ascii')
		message = data_bytes + timestamp #timestamp is always 26 bytes
		signed_message = self.sign(message)

		try:
			ciphertext = ctx.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
			full_message = ciphertext + signed_message + self.cert + self.pem + extra
		except:
			Exception("Encryption Failed")
		else:
			return full_message

	def decrypt(self, data):
		assert self.bank_public_key != None
		encrypted_data = data[:256]
		signed_data = data[256:512]
		cert = data[512:768]
		pem = data[768:1219]
		if len(data) > 1219:
			extra = data[1219:] #only ever used for recving cert from bank
		else:
			extra = None

		verification_level = -1

		try:
			ctx = serialization.load_pem_public_key(pem)
		except Exception as e:
			print(e)
		else:
			verification_level = 0


		try:
			self.verify(cert, pem)
		except Exception as e:
			print(e)
		else:
			verification_level = 1
		

		decrypted = self.private_key.decrypt(encrypted_data,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
		
		try:
			self.verify(signed_data, decrypted, ctx)
		except:
			Exception("Message Integrity Failed")

		plaintext = decrypted[:-26]
		timestamp = data[-26:]

		try:
			self.timestamp_check(timestamp)
		except:
			Exception("Invalid Timestamp")

		return plaintext, verification_level, pem, extra

	def timestamp_check(self, timestamp):
		now = datetime.utcnow()
		timestamp_time = datetime.fromisoformat(timestamp.decode('ascii'))
		assert int(str(now - timestamp_time)[5:7]) < 10

	def sign(self, data):
		sig = self.private_key.sign(data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
		return sig

	def verify(self,signed_data, data, ctx=None):	
		assert self.bank_public_key != None
		if ctx == None:
			ctx = self.bank_public_key
		ctx.verify(signed_data,data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
		
	def get_hash(self, data):
		digest = hashes.Hash(hashes.SHA256())
		digest.update(data)
		ret = digest.finalize()
		return ret





	def encrypt_from_pem(self, data, pem):
		ctx = serialization.load_pem_public_key(pem)
		ct = self.encrypt(data, ctx)
		return ct

	def encrypt_from_name(self, data, name):
		try:
			pem = self.key_chain[name]
		except:
			print("key not found")
			ct = None
		else:
			ct = encrypt_from_pem(data, pem)
		finally:
			return ct