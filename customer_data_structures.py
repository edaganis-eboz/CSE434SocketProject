
class Customer_Data(object):
	def __init__(self, name = None, addr = None):
		self.name = name #never changes
		self.addr = addr #never changes
		self.last_recv = 0
		self.first_sent = 0
		self.last_sent = 0
		

	def print(self):
		print(self.name, self.addr, self.last_recv, self.tentative_checkpoint, self.current_checkpoint)


#we dont need a last checkpoint cause we will never rollback twice
class State(object):
	def __init__(self, balance, cohort_data):
		self.balance = balance
		self.cohort_data = cohort_data




def main():
	name = 'alice'
	addr = ('127.0.0.1', 5432)
	x = Customer_Data(name, addr)
	x.print()
	


if __name__ == "__main__":
	main()
