import socket
import threading
import queue
import random

 
class Bank(object):
	def __init__(self):
		self.in_queue = queue.Queue() #queue of incoming commands
		self.out_queue = queue.Queue() #queue of things to send
		self.host = ''
		self.port = 12345
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.bind((self.host, self.port))
		self.customer_list = []
		self.cohort_list = []
		self.bank_main()


	def bank_main(self):
		threading.Thread(target=self.recv).start()
		threading.Thread(target=self.execute_command).start()
		threading.Thread(target=self.send).start()
		
			
	def recv(self): #produces in queue
		while True: #always listen
			data = self.sock.recvfrom(1024)
			if self.syntax_check(data[0]):
				self.in_queue.put(data)
			#print(f"Recv: {data[0].decode('ascii')} from {data[1]}")


	def execute_command(self): #consumes in queue, produces outqueue
		while True:
			while self.in_queue.empty() == False:
				msg = 'unknown command'
				data = self.in_queue.get()
				cmd = data[0].decode('ascii').split()
				if cmd[0] == 'open':
					msg = self.open_cmd(cmd, data[1])
				elif cmd[0] == 'new_cohort':
					msg = self.new_cohort(cmd)
				elif cmd[0] == 'del_cohort':
					msg = self.del_cohort(cmd)
				elif cmd[0] == 'exit':
					msg = self.exit_cmd(cmd)
				elif cmd[0] == 'debug_print':
					msg = self.debug_list_customers()
				out_msg = (msg.encode('ascii'), data[1])
				self.out_queue.put(out_msg)
		pass

	def send(self): #consumes out queue
		while True:
			while self.out_queue.empty() == False:
				data, addr = self.out_queue.get()
				self.sock.sendto(data, addr)
		pass

	def syntax_check(self, data): #this will check the syntax of the command (not needed for milestone :P)
		#command = data.decode('ascii').split(' ')
		#print(command)
		return True

	def open_cmd(self, cmd_list, addr):
		new_customer = Customer(cmd_list[1], cmd_list[2],addr[0], addr[1], cmd_list[3])
		self.customer_list.append(new_customer)
		msg = "SUCESSS"
		print('open cmd')
		self.debug_list_customers()
		return msg

	def new_cohort(self,cmd_list):
		print('new_cohort cmd', cmd_list)
		starting_customer_name = cmd_list[1]
		cohort_size = cmd_list[2]
		if int(cohort_size) <= len(self.customer_list): #this should be > cohortless
			new_id = random.randint(0,9999) #cohorts can have id collisons, this can be easily fixed
			self.cohort_list.append(new_id)
			for customer in self.customer_list:
				if customer.name == starting_customer_name:
					#will append multiple customers if they have same name
					customer.cohort_id = new_id
			added = 0
			no_cohort = []
			for i in range(len(self.customer_list)): #iterate through every customer
				if self.customer_list[i].cohort_id == -1:
					no_cohort.append(i) #get a list of the index of cohortless customers
	
			while added < int(cohort_size) -1:
				index = random.randint(0, len(no_cohort)-1)
				self.customer_list[no_cohort[index]].cohort_id = new_id
				added += 1
				del no_cohort[index]
			self.debug_print_cohort() #the new cohort is created at this point, now to just send to confirmation to the starter
			#time to create the return message
			for customer in self.customer_list:
				if customer.name == starting_customer_name:
					return_addr = (customer.ip_address, customer.portb)
					break
			msg = f"members in new cohort: {new_id}".encode('ascii')
			self.out_queue.put((msg, return_addr))
			for customer in self.customer_list:
				if customer.cohort_id == new_id:
					msg = customer.get_info().encode('ascii')
					self.out_queue.put((msg, return_addr))
			return "SUCESSS"
		else:
			return "FAILURE"
		

	def del_cohort(self, cmd_list):
		print('del_cohort cmd')
		customer_name = cmd_list[1]
		for customer in self.customer_list:
			if customer.name == customer_name:
				cohort_id = customer.cohort_id
				break

		for customer in self.customer_list:
			if customer.cohort_id == cohort_id:
				customer.cohort_id = -1
				msg = f"you have been removed from your cohort by: {customer_name}".encode('ascii')
				return_addr = (customer.ip_address, customer.portb)
				self.out_queue.put((msg, return_addr)) #send a message to all customers in a cohort that theyve been kicked
		self.cohort_list.remove(cohort_id)
		return "SUCESSS" 


	def exit_cmd(self, cmd_list):
		print('exit_cmd')
		customer_name = cmd_list[1]
		for customer in self.customer_list:
			if customer.name == customer_name:
				self.customer_list.remove(customer)
				return "SUCESSS"

		return "FAILURE"


	def debug_list_customers(self): #debug function
		for customer in self.customer_list:
			print(customer.get_info())


	def debug_print_cohort(self): #debug function
		for cohort in self.cohort_list:
			print(f"cohort: {cohort}")
			for customer in self.customer_list:
				if customer.cohort_id == cohort:
					print(customer.get_info())



class Customer(object):
	def __init__(self, name, balance, ip_address, portb, portp):
		self.name = name
		self.balance = balance
		self.ip_address = ip_address		
		self.portb = portb
		self.portp = portp
		self.cohort_id = -1

	def get_info(self):
		ret_str = str(self.name) + ' ' + str(self.balance) + ' ' + str(self.ip_address) + ' ' + str(self.portb) + ' ' + str(self.portp)
		return ret_str

class Cohort(object):  #deprecated for now
	customers = []
	def __init__(self, id):
		self.id = id
	def add_customer(self, customer):
		customer.cohort_id = self.id
		customers.append(customer)



def main():
	Bank()


if __name__ == "__main__":
	main()