
class Customer(object):
	def __init__(self, name, balance, ip_address, portb, portp, public_key):
		self.name = name
		self.balance = balance
		self.ip_address = ip_address		
		self.portb = portb
		self.portp = portp
		self.cohort_id = -1
		self.public_key = public_key #This is a serialized key?

	def get_info(self):
		ret_str = '[' + "'" +str(self.name)+ "'" + ',' + str(self.balance) + ',' + "'" +str(self.ip_address) + "'" +',' + str(self.portb) + ',' + str(self.portp) + ']'
		#print(len(ret_str))
		return ret_str

	def get_info_for_peer(self):
		ret_str = '[' + "'" +str(self.name)+ "'" + ',' + "'" +str(self.ip_address) + "'"  + ',' + str(self.portp) + ']'
		return ret_str

class Cohort(object):  #deprecated for now
	def __init__(self, id):
		self.id = id
		self.customers = []
	def add_customer(self, customer):
		customer.cohort_id = self.id
		self.customers.append(customer)

	def print_cohort(self):
		ret_str = ''
		for customer in self.customers:
			ret_str += customer.get_info()
			ret_str += '\n'
		return ret_str[:-1]


	def print_cohort_for_peer(self):
		ret_str = ''
		for customer in self.customers:
			ret_str += customer.get_info_for_peer()
			ret_str += '\n'
		return ret_str[:-1]


