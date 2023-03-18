#I would like to thank CSE340 for teaching me recursive parsing
class command_syntax_checker(object): #the function of this is to parse cmds and then output an array with args'
	def __init__(self):
		pass

	def _parse(self, raw_cmd):
		string_array = raw_cmd.lower().split(' ')
		return_array = self.cmd_parse(string_array)
		return return_array

	def cmd_parse(self, cmd):
		command = cmd[0]
		if (command == 'open'):
			return_array = [cmd[0]]
			return_array += self.open_parse(cmd[1:])
			return return_array

		elif (command == 'new_cohort'):
			return_array = [cmd[0]]
			return_array += self.new_cohort_parse(cmd[1:])
			return return_array

		elif (command == 'del_cohort'):
			return_array = [cmd[0]]
			return_array += self.del_cohort_parse(cmd[1:])
			return return_array

		elif (command == 'exit'):
			return_array = [cmd[0]]
			return_array += self.exit_parse(cmd[1:])
			return return_array

		else:
			return self.syntax_error()

##### OPEN CMD #######
	def open_parse(self, args):
		return_array = []
		try:
			return_array += self.parse_name(args[0])
			return_array += self.parse_balance(args[1])
			#return_array += self.parse_ip(args[2]) Not required These are gotten from the UDP header data, (not sent as a string over the wire)
			#return_array += self.parse_portb(args[3]) Not required
			return_array += self.parse_portp(args[2])
			#return_array += self.parse_token_hash(args[3]) #This is bytes
			#return_array += self.parse_public_key(args[4]) #This is a serialized rsa pubkey
		except:
			return self.syntax_error() #This catches if uncomplete cmd
		else:
			return return_array

	def parse_name(self, name):
		if len(name) > 0 and len(name) < 16:
			return [name] #name can be any string greater than zero
		else:
			return self.syntax_error()

	def parse_balance(self, balance):
		try:
			b = int(balance)
		except:
			return self.syntax_error()
		else:
			return [b]

	def parse_ip(self, ip):
		return [ip]

	def parse_portb(self, portb):
		return [portb]

	def parse_portp(self, portp):
		try:
			p = int(portp)
		except:
			return self.syntax_error()
		else:
			if p > 65565 or p < 1:
				return self.syntax_error()
			else:
				return [p]

##### NEW COHORT #######
	def new_cohort_parse(self, args):
		return_array = []
		try:
			return_array += self.parse_name(args[0])
			return_array += self.parse_n(args[1])
		except:
			return self.syntax_error()
		else:
			return return_array


	def parse_n(self, n):
		try:
			nut = int(n)
		except:
			return self.syntax_error()
		else:
			if nut < 1:
				return self.syntax_error()
			else:
				return [nut]

##### DEL COHORT ######

	def del_cohort_parse(self, args):
		return_array = []
		try:
			return_array += self.parse_name(args[0])
		except:
			return self.syntax_error()
		else:
			return return_array

##### EXIT #####

	def exit_parse(self, args):
		return_array = []
		try:
			return_array += self.parse_name(args[0])
		except Exception as e:
			print(e)
			return self.syntax_error()
		else:
			return return_array


	def syntax_error(self):
		return ['syntax error']


##### TESTING #####
def main():
	test = command_syntax_checker()
	y = input()
	output = test._parse(y)
	print(output)

if __name__ == "__main__":
	main()

