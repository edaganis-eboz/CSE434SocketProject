#this parser is kinda shitty, it might need a lexer

class parser(object):
	def __init__(self):
		pass

	def _parse(self, raw_cmd):
		string_array = raw_cmd.lower().split(' ')
		return_array = self.cmd_parse(string_array)
		return return_array

	def cmd_parse(self, cmd):
		if (cmd[0] == 'open' or
		cmd[0] == 'new_cohort' or
		cmd[0] == 'del_cohort' or
		cmd[0] == 'exit'):
			res = ['bankcmd']
			#res = " ".join([str(item) for item in cmd])
			return res
		elif cmd[0] == 'deposit':
			return_array = [cmd[0]]
			return_array += self.deposit_parse(cmd[1])
			return return_array
		elif cmd[0] == 'withdrawl':
			return_array = [cmd[0]]
			return_array += self.deposit_parse(cmd[1]) #sic
			return return_array
		elif cmd[0] == 'transfer':
			return_array = [cmd[0]]
			return_array += self.transfer_parse(cmd[1:])
			return return_array
		elif cmd[0] == 'lost_transfer':
			return_array = [cmd[0]]
			return_array += self.lost_transfer_parse(cmd[1:])
			return return_array
		elif cmd[0] == 'checkpoint':
			return_array = [cmd[0]]
			return_array += self.checkpoint_parse(cmd[1:])
			return return_array
		elif cmd[0] == 'rollback':
			return_array = [cmd[0]]
			return_array += self.rollback_parse(cmd[1:])
			return return_array
		elif cmd[0] == 'ping': #bad
			return cmd
		elif cmd[0] == 'ping_cohort': #bad
			return cmd
		elif cmd[0] == 'print': #bad
			return cmd
		elif cmd[0] == 'key': #bad
			return cmd
		elif cmd[0] == 'take_tentative_checkpoint':
			#cmd = cmd[0] + labelpases
			return cmd
		elif cmd[0] == 'checkpoint_decision':
			return cmd
		elif cmd[0] == 'initiate_rollback':
			#cmd = cmd[0] + labelpases
			return cmd
		elif cmd[0] == 'rollback_decision':
			return cmd
		else:
			return self.syntax_error()

	def transfer_parse(self, args):
		return_array = self.deposit_parse(args[0])
		return_array += self.q_parse(args[1])
		if len(args) > 2:
			return_array += self.deposit_parse(args[2])
		return return_array
	def lost_transfer_parse(self, args):
		return_array = self.deposit_parse(args[0])
		return_array += self.q_parse(args[1])
		return return_array
	
	def checkpoint_parse(self, args):
		return args
	def rollback_parse(self, args):
		return args

	def deposit_parse(self, args):
		try:
			amount = int(args)
		except:
			return self.syntax_error()
		if amount < 0:
			return self.syntax_error()
		else:
			return_array = [amount]
		return return_array

	

	def q_parse(self, args): #this is the destination, 
		return [args]
	



	def syntax_error(self):
		return ["syntax error"]


def main():
	test = parser()
	while True:
		x = input()
		print(test._parse(x))
if __name__ == "__main__":
	main()
