import socket

def main():
	host = ''
	port = 12345
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	while True:
		msg = input("$")
		sock.sendto(msg.encode('ascii'), (host,port))
		echo = sock.recvfrom(1024)
		print(f"Recv: {echo}")



if __name__ == "__main__":
	main()