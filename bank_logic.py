import bank_syntax_checker
import bank_data_objects
import bingus

import os, random, queue
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

class bank_logic(object):
	def __init__(self, output_q):
		self.syntax_checker = bank_syntax_checker.command_syntax_checker()
		self.database = []
		self.cohorts = []
		self.bingus = bingus.Bingus()
		self.bingus.bank_public_key = self.bingus.public_key
		self.bingus.cert = self.bingus.sign(self.bingus.pem)
		self.bingus.is_bank = 1
		self.output_q = output_q


	def cryptographic_entry(self, data, addr):
		if data == b'key_request':
			msg = self.bingus.pem
			return msg
		else:
			try:
				cmd, verification_level, pem, extra = self.bingus.decrypt(data)
				cmd = cmd.decode('ascii') 
				print(cmd)
				msg = self.execute_cmd(cmd, verification_level, pem, addr)
				return msg
			except:
				Exception("Failed at cryptographic_entry")


	def execute_cmd(self, cmd, verification_level, pem, addr): #these functions are going to return cryptographic_exit(msg)
		ret_msg = 'error'
		parsed = self.syntax_checker._parse(cmd)   #maybe dont use a switch satement here..... peer should only be able to open 1 acc....
		if 'syntax error' not in parsed:
			if (verification_level == 1):
				name = parsed[1]
				if self.get_pem(name) != pem:
					ret_msg = b'Wrong Guy Bucko'
					return self.cryptographic_exit(ret_msg, pem) 

			if parsed[0] == 'open':
				if (verification_level == 0): 
					try:
						ret_msg = self.opencmd(parsed[1:], addr, pem)
					except Exception as e:
						print(e)
				else:
					ret_msg = "client already has account"
					
			elif parsed[0] == 'new_cohort':
				if (verification_level == 1): 
					try:
						ret_msg = self.new_cohort(parsed[1:])
					except Exception as e:
						print(e)
				else:
					ret_msg = "client does not have account"
				
			elif parsed[0] == 'del_cohort':
				if (verification_level == 1): 
					try:
						ret_msg = self.del_cohort(parsed[1:])
					except Exception as e:
						print(e)
				else:
					ret_msg = "client does not have account"
			
			elif parsed[0] == 'exit':
				if (verification_level == 1): 
					try:
						ret_msg = self.exit(parsed[1:])
					except Exception as e:
						print(e)
				else:
					ret_msg = "client does not have account"
					
			else:
				ret_msg = "something went wrong"		
		else:
			#print("syntax error")
			ret_msg = 'syntax error'

		return self.cryptographic_exit(ret_msg, pem)


	def cryptographic_exit(self, data, pem): 
		if type(data) == tuple:
			extra = data[1]
			dataa = data[0]
		else:
			dataa = data
			extra = b''

		ctx = serialization.load_pem_public_key(pem)
		enc = self.bingus.encrypt(dataa, ctx)
		return enc + extra
		

	def opencmd(self, args, addr, pem):
		if not self.name_exists(args[0]):
			try:
				new_customer = bank_data_objects.Customer(args[0], args[1], addr[0], addr[1], args[2], pem)
				self.database.append(new_customer)
			except Exception as e:
				print(e)
				return b'FAILURE'
			else:
				cert = self.bingus.sign(pem)
				return b'SUCCESS', cert
		else:
			return b'FAILURE: NAME EXISTS'
	

	def new_cohort(self, args):
		seed_name = args[0]
		cohort_size = int(args[1])
		cohortless = [] #this is gonna be an array customers without cohort

		for customer in self.database:
			if customer.cohort_id == -1:
				cohortless.append(customer)

		if cohort_size <= len(cohortless): 
			try:
				new_id = random.randint(0,99999999) #cohorts can have id collisons, this can be easily fixed
				new_cohort = bank_data_objects.Cohort(new_id)
				
				
				for customer in cohortless:
					if customer.name == seed_name:
						assert customer.cohort_id == -1
						new_cohort.add_customer(customer)
						cohortless.remove(customer)
						break
				
				added = 1
				while added < int(cohort_size):
					index = random.randint(0, len(cohortless)-1)
					to_be_added = cohortless[index]
					new_cohort.add_customer(to_be_added)
					cohortless.remove(to_be_added)
					added += 1

				for customer in new_cohort.customers:
					dat = b'CD:' + new_cohort.print_cohort_for_peer().encode('ascii')
					msg = self.create_direct_message(customer.name, dat)
					self.output_q.put(msg)
			except Exception as e:
				print(e)
				return b'FAILURE'
			else:
				self.cohorts.append(new_cohort)
				return b"SUCCESS\n" + new_cohort.print_cohort_for_peer().encode('ascii')
		else:
			return b"FAILURE"

	def del_cohort(self, args):
		seed_name = args[0]
		cohort_id = -1
		working_cohort = None
		for customer in self.database:
			if customer.name == seed_name:
				cohort_id = customer.cohort_id
		if cohort_id == -1:
			return b'FAILURE'
		for cohort in self.cohorts:
			if cohort.id == cohort_id:
				working_cohort = cohort

		if working_cohort == None:
			return b'FAILURE'
		for customer in working_cohort.customers:
			customer.cohort_id = -1
			del_msg = f"you have been removed from cohort by {seed_name}"
			try:
				msg = self.create_direct_message(customer.name, del_msg)
			except:
				pass
			else:
				self.output_q.put(msg)
		self.cohorts.remove(working_cohort)
		return b'SUCCESS'


	def exit(self, args):
		name = args[0]
		to_be_removed = None
		for customer in self.database:
			if customer.name == name:
				to_be_removed = customer
		try:
			self.database.remove(to_be_removed)
		except:
			return b'FAILURE'
		else:
			return b'SUCCESS'


	def create_direct_message(self, name, data):
		pem = self.get_pem(name)
		ct = self.bingus.encrypt_from_pem(data, pem)
		addr = self.get_addr(name)
		return (ct, addr)




############## DEBUG #####################
	def debug_list_customers(self): #debug function
		ret_string = ''
		for customer in self.database:
			ret_string += (customer.get_info() + '\n')
		return ret_string[:-1]
	
	def debug_print_cohorts(self): #debug function
		for cohort in self.cohorts:
			print(f"cohort: {cohort.id}")
			print(cohort.print_cohort())

	def name_exists(self, name):
		ret = False
		for customer in self.database:
			if customer.name == name:
				ret = True
		return ret

	def get_pem(self, name):
		ret = None
		for customer in self.database:
			if customer.name == name:
				ret = customer.public_key
		if ret == None:
			raise Exception("key not found")
		else:
			return ret

	def get_addr(self, name):
		ret = None
		for customer in self.database:
			if customer.name == name:
				ret = (customer.ip_address, customer.portb)
		if ret == None:
			raise Exception("addr not found")
		else:
			return ret