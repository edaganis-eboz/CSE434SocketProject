import socket
import random
import threading 


class customer(object):
	def __init__(self):
		self.bank_host = '' #localhost
		self.bank_port = 12345 #dummy
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #udp port
		self.customer_main()


	def customer_main(self):
		threading.Thread(target=self.listen).start() #multithreading so it can send a recv at the same time
		threading.Thread(target=self.send).start() #might have to include queues when peer to peer toggles on
		

	def listen(self):
		while True:
			global kill #i have no clue if this is the correct way to stop a multithreaded program in python
			if kill:
				break
			message, addr = self.sock.recvfrom(1024)
			print(f"Recv: {message.decode('ascii')}")

	def send(self):
		while True:
			global kill
			if kill:
				break
			msg = input()
			self.sock.sendto(msg.encode('ascii'), (self.bank_host,self.bank_port))
			if msg.split(' ')[0] == 'exit':
				print("Exiting....")
				kill = True
				exit(0)

def main():
	global kill
	kill = False
	customer()

if __name__ == "__main__":
	main()