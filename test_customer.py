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
		threading.Thread(target=self.listen).start()
		threading.Thread(target=self.send).start()
		

	def listen(self):
		while True:
			message, addr = self.sock.recvfrom(1024)
			print(f"Recv: {message.decode('ascii')}")

	def send(self):
		while True:
			msg = input()
			self.sock.sendto(msg.encode('ascii'), (self.bank_host,self.bank_port))

def main():
	customer()

if __name__ == "__main__":
	main()