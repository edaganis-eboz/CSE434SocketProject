import socket, random, os, threading, select, queue, time
import bingus
import customer_syntax_checker
import customer_checkpoint
from customer_data_structures import Customer_Data, State
from datetime import datetime
from ast import literal_eval 
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization


class customer(object):
	def __init__(self):
		self.bank_host = '' #localhost
		self.bank_port = 12345 #dummy
		self.bank_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #udp port
		self.bank_lock = threading.Lock()

		self.peer_host = ''
		self.peer_port = 55555
		self.peer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


		self.cohort_data = []
		self.balance = 0
		self.name = None
		self.tentative = None
		self.state = None  #this is the checkpoint state
		self.ok_to_take_checkpoint = True
		self.exit_flag = 0
		self.rollback_state = 0
		self.parser = customer_syntax_checker.parser()
		self.control_messages = [b'checkpoint',
		b'checkpoint_successful', b'checkpoint_unsuccessful',
		b'checkpoint_decision make_tentative_permanant', b'checkpoint_decision delete_tentative', b'rollback',
		b'rollback_able', b'rollback_unable', b'rollback yes', b'rollback no', b'checkpoint_decision', b'initiate_rollback', b'rollback_decision']

		self.bingus = bingus.Bingus()

		self.bank_queue = queue.Queue() #this is to send stuff to the bank
		self.peer_queue = queue.Queue() #this is to send stuff to peers
		self.control_message_q = queue.Queue() #is is to send stuff to the self logic proc
		self.customer_init()
		self.customer_main()


	def customer_init(self):
		self.bank_sock.sendto(b'key_request', (self.bank_host, self.bank_port)) #begin the handshake
		bank_pubkey_string = self.bank_sock.recvfrom(2048) #get the pub key
		self.bingus.bank_public_key = serialization.load_pem_public_key(bank_pubkey_string[0])
		print("Init Complete")

	def customer_main(self):
		threading.Thread(target=self.customer_cli).start()
		threading.Thread(target=self.bank_handler).start()
		threading.Thread(target=self.peer_handler).start()

	def customer_cli(self):
		while True:
			global kill
			if kill:
				break
			cmd = input()
			if len(cmd) > 100:
				print("Command must be less than 100 characters")
			elif cmd == 'kill':
				kill = True
			elif self.is_self_cmd(cmd):
				parsed = self.parser._parse(cmd)
				self.self_cmd(parsed)			
			elif len(cmd) > 1:
				parsed = self.parser._parse(cmd)
				if parsed[0] == 'bankcmd':  #is this a command im going to send to the bank?
					if cmd[:4] == 'exit':
						self.exit_flag = 1
					if cmd.split(' ')[0] == 'open' and self.name == None:
						self.name = cmd.split(' ')[1]
						self.balance = int(cmd.split(' ')[2])
						self.peer_port = int(cmd.split(' ')[3]) #this is really bad, no syntax checking
						self.peer_sock.bind((self.peer_host, self.peer_port))
					self.bank_queue.put(cmd)
				else:
					if 'syntax error' not in parsed:
						#print("A peer command:", parsed)
						self.peer_logic(parsed)
					else:
						print('syntax error')
			else:
				pass

	def bank_handler(self):
		threading.Thread(target=self.bank_sender).start()
		threading.Thread(target=self.bank_listener).start()

	def bank_sender(self):	
		while True:
			global kill
			if kill:
				break
			if self.bank_queue.empty() == False:
				cmd = self.bank_queue.get()
				try:
					ct = self.bingus.encrypt(cmd)
				except:
					print("encryption failed")
				else:
					self.bank_sock.sendto(ct, (self.bank_host, self.bank_port))
				
	def bank_listener(self):
		while True:
			global kill
			if kill:
				break
			ready = select.select([self.bank_sock], [], [], 0.1)
			if ready[0]:
				recv_data, addr = self.bank_sock.recvfrom(2048)
				try:
					pt, verification, pem, extra  = self.bingus.decrypt(recv_data)
				except Exception as e:
					print("decryption failed")
					print(e)
				else:
					if self.bingus.cert == bytes(256) and extra != None: #this is a bad idea
						self.bingus.cert = extra #this is hella sketchy
						print("New Cert")
					
					if pt == b'SUCCESS' and self.exit_flag == 1:
						kill = True
						print("Press Enter to Exit")
					else:
						self.exit_flag = 0
					
					if pt[:3] == b'CD:' and self.cohort_data == []:
						self.set_cohort_data(pt[3:])	
					elif pt[:36] == b'you have been removed from cohort by':
						self.cohort_data = []
						self.key_chain = []
						print(pt.decode('ascii'))
					else:
						print(pt.decode('ascii'))

					
	def peer_handler(self):
		threading.Thread(target=self.peer_sender).start()
		threading.Thread(target=self.peer_listener).start()


	def peer_sender(self):
		while True:
			global kill
			if kill:
				break
			if self.peer_queue.empty() == False:
				message, addr = self.peer_queue.get()
				try:
					if message[:3] != b'key':
						if not self.is_control_msg(message):
							message += self.add_update_label(addr) 
						pem = self.get_pem_from_addr(addr)
						ct = self.bingus.encrypt_from_pem(message, pem.encode('ascii'))
						self.peer_sock.sendto(ct, addr)
					else:
						self.peer_sock.sendto(message, addr)
				except Exception as e:
					print(e)
					print("encryption failed")
				else:
					print(f"Sending message {message} to {addr}")

	def peer_listener(self):
		while True:
			global kill
			if kill:
				break
			ready = select.select([self.peer_sock], [], [], 0.1)
			while ready[0]:
				recv_data, addr = self.peer_sock.recvfrom(2048)
				if recv_data[:3] != b'key':	
					try:
						recv_data, _, _, _ = self.bingus.decrypt(recv_data)
						print(f"recv: {recv_data} from {addr}")
					except Exception as e:
						print(e)
					else:
						if self.is_control_msg(recv_data):
							parsed = self.parser._parse(recv_data.decode('ascii')) #make a unique to parse control messages
							if parsed[0] == "checkpoint" or parsed[0] == 'initiate_rollback' or parsed[0] == 'rollback_decision':
								self.peer_logic(parsed, addr)
							else:
								self.control_message_q.put((recv_data,addr))
						else:
							parsed = self.parser._parse(recv_data.decode('ascii'))
							if parsed[0] != 'take_tentative_checkpoint':
								self.check_recv_lab(int(parsed[-1:][0]), addr)
								self.peer_logic(parsed[:-1], addr)
							else:
								self.peer_logic(parsed,addr)
				else:
					#only key messages should reach here so this should be ok
					s = recv_data.decode('ascii')
					key_cmd = s.split(' ', 1)[0]
					name = s.split(' ', 2)[1]
					pem = s.split(' ', 2)[2]
					parsed = [key_cmd] + [name] + [pem]
					self.peer_logic(parsed, addr)
				


	def peer_logic(self,cmd,addr=None):
		if cmd[0] == 'transfer':
			self.transfer(cmd[1], cmd[2], addr)
		elif cmd[0] == 'lost_transfer':
			self.lost_transfer(cmd[1], cmd[2])
		elif cmd[0] == 'checkpoint':   #TODO make it so the intermediate checkpoint messages cannot be trigged via cli, same with rollback, jesus forgive me
			self.init_checkpoint()
		elif cmd[0] == 'take_tentative_checkpoint':
			t1 = threading.Thread(target=self.recv_checkpoint, args = ((cmd[0], addr))).start()
		elif cmd[0] == 'checkpoint_decision':
			self.checkpoint_delperm(cmd[1])
		elif cmd[0] == 'rollback':
				self.rollback_send()
		elif cmd[0] == 'initiate_rollback':
				self.rollback_recv_stage_1(cmd, addr)
		elif cmd[0] == 'rollback_decision':
				self.rollback_recv_stage_2(cmd, addr)
		elif cmd[0] == 'key':
			self.multicast_key(cmd)
		elif cmd[0] == 'ping':
			if len(cmd) != 2:
				print(f"{cmd[0]} from {addr}")
			elif len(cmd) == 2:
				try:
					self.send_to_name(cmd[1], b'ping')
				except Exception as e:
					print(e)
		elif cmd[0] == 'ping_cohort':
			self.multicast_to_cohort('ping')
		else:
			print("error")


	def is_self_cmd(self, cmdy):
		cmd = cmdy.split(' ')[0]
		if cmd == 'print' or cmd == 'deposit' or cmd == 'withdrawl':
			return True
		else:
			return False

	def self_cmd(self, cmd):
		if cmd[0] == 'print':
			print(self.name, self.balance, self.peer_port)
			#print(self.bingus.key_chain)
		elif cmd[0] == 'deposit':
			self.deposit(int(cmd[1]))
		elif cmd[0] == 'withdrawl':
			self.withdrawl(int(cmd[1]))
		else:
			print("something went wrong")

	def deposit(self, amount):
		self.balance += amount

	def withdrawl(self, amount):
		self.balance -= amount

	def set_cohort_data(self, data):
		print("Loading Cohort Data...")
		d = data.decode('ascii').split('\n')
		p = []
		for guy in d:
			arrayd = literal_eval(guy) # [name, ip, peer_port] 
			if True:#arrayd[0] != self.name:
				data_object = Customer_Data(arrayd[0], (arrayd[1], arrayd[2]))
				p.append(data_object)
		self.cohort_data = p
		self.state = State(self.balance, self.cohort_data)
		time.sleep(1) #avoid race condition
		self.multicast_key()

	def get_name(self, addr):
		ret = None
		for customer in self.cohort_data:
			if customer.addr == addr:
				ret = customer.name
		if ret == None:
			raise Exception("name not found")
		else:
			return ret 

	def get_addr(self, name):
		ret = None
		for customer in self.cohort_data:
			if customer.name == name:
				ret = customer.addr
		if ret == None:
			raise Exception("addr not found")
		else:
			return ret

	def add_update_label(self, addr):
		destination = None
		for customer in self.cohort_data:
			if customer.addr == addr:
				destination = customer
		if destination == None:
			raise Exception("Not Found")
		else:
			destination.first_sent += 1
			destination.last_sent += 1

			ret_str = b" " + str(destination.first_sent).encode('ascii')
			
			return ret_str

	def check_recv_lab(self, label, addr):
		source = None
		for customer in self.cohort_data:
			if customer.addr == addr:
				source = customer
		if source == None:
			raise Exception("Not Found")
		else:
			excepted = source.last_recv + 1
			if excepted == label:
				source.last_recv = label
			else:
				self.ok_to_take_checkpoint = False
				print("Unexpected Message:Inconsistent State")

	def multicast_to_cohort(self, msg): #mulicasts to everyone in cohort
		if type(msg) != bytes:
			msg = msg.encode('ascii')
		for customer in self.cohort_data:
			if customer.name != self.name:
				addr = customer.addr
				self.peer_queue.put((msg, addr))

	def send_to_name(self, name, message):
		if type(message) != bytes:
			message = message.encode('ascii')
		addr = self.get_addr(name)
		self.peer_queue.put((message, addr))

	def is_control_msg(self, cmd):
		cmd = cmd.decode('ascii').split(' ')
		cmd0 = cmd[0]
		cmd1 = cmd0.encode('ascii') #FML
		if cmd1 in self.control_messages:
			return True
		else:
			return False

	def init_checkpoint(self): #this is initalized when the cli gets 'checkpoint'
		self.control_messages.append(b'take_tentative_checkpoint')
		chkpnt_cohort = []
		for customer in self.cohort_data:
			if customer.last_recv != 0:
				chkpnt_cohort.append(customer)
	
		if len(chkpnt_cohort) == 0:
			pass #do nothing?
		else:
			nom = len(chkpnt_cohort)
			recv = 0
			for customer in chkpnt_cohort:
				msg = b'take_tentative_checkpoint' #+ (" " + str(customer.last_recv)).encode('ascii')
				self.peer_queue.put((msg, customer.addr))
	
			while recv < nom:
				make_perm = True
				if self.control_message_q.empty() == False:
					response, addr = self.control_message_q.get()
					if response == b'checkpoint_unsuccessful':
						make_perm = False
						recv += 1
					elif response == b'checkpoint_successful':
						recv += 1
					elif response == b'take_tentative_checkpoint':
						if self.tentative != None:
							self.peer_queue.put((b'checkpoint_successful', addr))
						elif self.ok_to_take_checkpoint == True:
							self.tentative = State(self.balance, self.cohort_data)
							self.peer_queue.put((b'checkpoint_successful', addr))
						else:
							self.peer_queue.put((b'checkpoint_unsuccessful', addr))
					else:
						print("DEBUG: 3213")
	
			if make_perm == True:
				if self.tentative == None:
					self.tentative = State(self.balance, self.cohort_data)

				for customer in chkpnt_cohort:
					msg = b'checkpoint_decision make_tentative_permanant'
					self.peer_queue.put((msg, customer.addr))
				
				self.state = self.tentative
				self.tentative = None
			else:
				for customer in chkpnt_cohort:
					msg = b'checkpoint_decision delete_tentative'
					self.peer_queue.put((msg, customer.addr))
				self.tentative = None
			self.control_messages.remove(b'take_tentative_checkpoint')
	

	def recv_checkpoint(self, data, addr): #this is initialized when you recv a take_tentative_checkpont
		if self.tentative != None:
			self.peer_queue.put((b'checkpoint_successful', addr))
		else:	
			chkpnt_cohort = []
			for customer in self.cohort_data:
				if customer.last_recv != 0:
					chkpnt_cohort.append(customer)
		
			if len(chkpnt_cohort) == 0:
				if self.ok_to_take_checkpoint == True:
					self.tentative = Customer_Data(self.balance, self.cohort_data)
					self.peer_queue.put((b'checkpoint_successful', addr))
				else:
					self.peer_queue.put((b'checkpoint_unsuccessful', addr))
	
			else:
				nom = len(chkpnt_cohort)
				recv = 0
				self.control_messages.append(b'take_tentative_checkpoint')
				for customer in chkpnt_cohort:
					msg = b'take_tentative_checkpoint'# + (" " + str(customer.last_recv)).encode('ascii')
					self.peer_queue.put((msg, customer.addr))
				while recv < nom:
					### WE ARE STUCK HERE, WHEN WE ARE IN THIS LOOP, NOTHING GETS THROUGH TO CONTROL MESSAGE
					my_response = True
					if self.control_message_q.empty() == False:
						response, r_addr = self.control_message_q.get()
						if response == b'checkpoint_unsuccessful':
							my_response = False
							recv += 1
						elif response == b'checkpoint_successful':
							recv += 1
						elif response == b'take_tentative_checkpoint':
							if self.ok_to_take_checkpoint == True:
								self.tentative = Customer_Data(self.balance, self.cohort_data)
								self.peer_queue.put((b'checkpoint_successful', r_addr))
							else:
								self.peer_queue.put((b'checkpoint_unsuccessful', r_addr))
						else:
							print("DEBUG: 3453")
	
				if my_response:
					self.peer_queue.put((b'checkpoint_successful', addr))
				else:
					self.peer_queue.put((b'checkpoint_unsuccessful', addr))

				self.control_messages.remove(b'take_tentative_checkpoint')
	
	
	def checkpoint_delperm(self, data):
		print(data)
		if data == 'make_tentative_permanant':
			self.state = self.tentative
			self.tentative = None
		elif data == 'delete_tentative':
			self.tentative = None
		else:
			raise Exception("error in checkpoint_delperm")
	

	def transfer(self, amount, dest, addr):
		if addr == None:
			self.withdrawl(amount)
			self.send_to_name(dest, f'transfer {amount} {dest}')
		else: #you are recving
			self.deposit(amount)
			print(f'Recv ${amount} from {addr}')
	
	def lost_transfer(self, amount, dest):
		self.withdrawl(amount)
		addr = self.get_addr(dest)
		self.add_update_label(addr)

	def rollback_send(self):
		chkpnt_cohort = []
		for customer in self.cohort_data:
			if customer.last_recv != 0:
				chkpnt_cohort.append(customer)
	
		if len(chkpnt_cohort) == 0:
			pass
		else:
			nom = len(chkpnt_cohort)
			recv = 0
			for customer in chkpnt_cohort:
				msg = b'initiate_rollback' #+ (" " + str(customer.last_recv)).encode('ascii')
				self.peer_queue.put((msg, customer.addr))

		x = True
		while recv < nom:
			if self.control_message_q.empty() == False:
				data = self.control_message_q.get()
				recv += 1
				if data == b'rollback_unable':
					x = False
		if x:
			while True:
				response = input("rollback ready, procceed y/n?")
				if response == 'y':
					for customer in chkpnt_cohort:
						msg = b'rollback_decision yes' #+ (" " + str(customer.last_recv)).encode('ascii')
						self.peer_queue.put((msg, customer.addr))
					self.balance = self.state.balance
					self.cohort_data = self.state.cohort_data
					self.ok_to_take_checkpoint = True
					break
				elif response == 'n':
					for customer in chkpnt_cohort:
						msg = b'rollback_decision no' #+ (" " + str(customer.last_recv)).encode('ascii')
						self.peer_queue.put((msg, customer.addr))
					break
				else:
					pass
		else:
			print("rollback failed")
			self.multicast_to_checkpoint_cohort(b'rollback no')

	def rollback_recv_stage_1(self, data, addr):
		if True:
			self.peer_queue.put((b'rollback_able', addr))
		else:
			self.peer_queue.put((b'rollback_unable', addr))

	def rollback_recv_stage_2(self, data, addr):
		if data[1] == 'yes':
			print('Rolling Back....')
			self.balance = self.state.balance
			self.cohort_data = self.state.cohort_data
			self.ok_to_take_checkpoint = True
		elif data[1] == 'no':
			pass
		else:
			raise Exception('Error with rollback')



#### BINGUS #####

	def multicast_key(self, data=None):
		time.sleep(1) #waiting to avoid race condition
		if data == None:
			#print("type1")
			if len(self.bingus.key_chain) < len(self.cohort_data):
				if self.cohort_data[len(self.bingus.key_chain)].name == self.name:
					self.multicast_to_cohort(f"key {self.name} {self.bingus.pem.decode('ascii')}")
		else:
			#print("type2")
			to_add = {data[1]:data[2]}
			self.bingus.key_chain.update(to_add) 
			if len(self.bingus.key_chain) < len(self.cohort_data):
				if self.cohort_data[len(self.bingus.key_chain)].name == self.name:
					self.multicast_to_cohort(f"key {self.name} {self.bingus.pem.decode('ascii')}")
			
	def get_pem_from_addr(self, addr):
		dest_name = self.get_name(addr)
		pem = self.bingus.key_chain[dest_name]
		return pem

	def encrypt_message(self, data, destination):
		if type(destination) == tuple:
			name = self.get_name(destination)
			addr = destination
		elif type(destination) == str:
			name = destination
			addr = self.get_addr(name)
		else:
			print('error')
		ct = self.bingus.encrypt_from_name(data, name)
		return (ct, addr) #not needed?




def main():
	global kill
	kill = False
	customer()

if __name__ == "__main__":
	main()


