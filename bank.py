import socket, threading, queue, select
import test_save, bank_logic


class Bank(object):
	def __init__(self):
		self.in_queue = queue.Queue() #queue of incoming commands
		self.out_queue = queue.Queue() #queue of things to send
		self.logic_queue = queue.Queue()
		self.host = ''
		self.port = 12345
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.bind((self.host, self.port))
		self.saveload = test_save.Save_Object()
		self._bank = bank_logic.bank_logic(self.logic_queue)
		
		self.bank_main()


	def bank_main(self):
		print("!!!!Welcome to BingusBank!!!!")
		threading.Thread(target=self.bank_cli).start()
		threading.Thread(target=self.recv).start()
		threading.Thread(target=self.execute_command).start()
		threading.Thread(target=self.send).start()

	def bank_cli(self):
		while True:
			global kill
			if kill:
				break
			cmd = input('$')
			if cmd.lower().split(' ')[0] == "kill":
				kill = True
			elif cmd.lower().split(' ')[0] == "list":
				out = self._bank.debug_list_customers()
				print(out)
			elif cmd.lower().split(' ')[0] == "cohorts":
				self._bank.debug_print_cohorts()
			else:	
				print(cmd)
					
	def recv(self): #produces in queue
		while True: #always listen
			global kill
			if kill:
				break
			ready = select.select([self.sock], [], [], 0.1)
			if ready[0]:
				data = self.sock.recvfrom(2048)
				self.in_queue.put(data)
				#print(f"DEBUG_Recv: {data[0].decode('ascii')} from {data[1]}")

	def execute_command(self): #consumes in queue, produces outqueue
		while True:
			global kill
			if kill:
				break 
			if self.in_queue.empty() == False: 
				msg = 'debug_message'
				data, addr = self.in_queue.get()
					
				msg = self._bank.cryptographic_entry(data, addr)			
				
				out_msg = (msg, addr) 
				self.out_queue.put(out_msg)

	def send(self): #consumes out queue
		while True:
			global kill
			if kill:
				break
			if self.out_queue.empty() == False:
				data, addr = self.out_queue.get()
				if data != None:
					self.sock.sendto(data, addr)
				else:
					print("data is none type")
			if self.logic_queue.empty() == False:
				data, addr = self.logic_queue.get()
				if data != None:
					self.sock.sendto(data, addr)
				else:
					print("data is none type")







#		
#
#	def del_cohort(self, cmd_list):
#		print('del_cohort cmd')
#		customer_name = cmd_list[1]
#		for customer in self.customer_list:
#			if customer.name == customer_name:
#				cohort_id = customer.cohort_id
#				break
#
#		for customer in self.customer_list:
#			if customer.cohort_id == cohort_id:
#				customer.cohort_id = -1
#				msg = f"you have been removed from your cohort by: {customer_name}".encode('ascii')
#				return_addr = (customer.ip_address, customer.portb)
#				self.out_queue.put((msg, return_addr)) #send a message to all customers in a cohort that theyve been kicked
#		self.cohort_list.remove(cohort_id)
#		return "SUCESSS" 
#


def main():
	global kill
	kill = False
	Bank()


if __name__ == "__main__":
	main()

