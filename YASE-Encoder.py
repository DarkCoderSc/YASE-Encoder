#!/usr/bin/python3

"""
	Jean-Pierre LESUEUR (@DarkCoderSc)
	https://www.phrozen.io/
	jplesueur@phrozen.io

	YASE Encoder : Yet Another Sub-Encoder

	License: MIT

	Category: OSCE Preparation	

	***
		I'm using bruteforcing in order generate the subs with valid characters.

		Valid characters are shuffled in order to output different looking subs each time you use the script
		even for exam same instructions.

		Be sure to understand what sub encoding is before using any automated scripts otherwise you will miss 
		something really cool to learn :)
	***

	TODO:
		- Optimize required amount of sub to limit size of output payload (actually always three subs)
"""

from textwrap import wrap
import numpy as np
import argparse
import random
import struct
import sys

_asm_push_eax = "\\x50"
_asm_push_ebx = "\\x53"
_asm_pop_eax = "\\x58"
_asm_pop_ebx = "\\x5b"
_asm_and = "\\x25"
_asm_sub = "\\x2d"

raw_output = False
verbose = True


class tcolors:
	clear = "\033[0m"
	green = "\033[32m"
	red = "\033[31m"
	yellow = "\033[33m"
	blue = "\033[34m"
	gray = "\033[90m"


def success(message):
	if raw_output or not argv.verbose:
		return

	print(f"[\033[32m✓\033[39m] {message}")


def error(message):
	if raw_output or not argv.verbose:
		return

	print(f"\033[31m{message}\033[39m")


def debug(message):
	if raw_output or not argv.verbose:
		return

	print(f"[\033[34m*\033[39m] {message}")	


def title(title):
	if raw_output or not argv.verbose:
		return

	print("\n" + ("=" * 45))
	print(f" {title}")
	print("=" * 45)


def bytearr_to_bytestr(data):
	return ''.join(f"\\x{'{:02x}'.format(x)}" for x in data)


def bytestr_to_bytearr(data):
	return list(bytearray.fromhex(data.replace("\\x", " ")))


"""
	Prepare our goodchar array. To vary the output subencoded shellcode, we generate
	goodchar list randomly. We can do this since we are bruteforcing correct sub combination.

	The goodchar is composed of alpha numeric characters from 0x01 to 0x7f.

	Notice: It is possible to filter even more badchars within the range of 0x01-0x7f,
		    use remove(character_to_remove).
"""
goodchars = [] # to be generated

def generate_goodchars():
	global goodchars

	goodchars = list(range(1, 128)) # 0x01 --> 0x7f

	random.shuffle(goodchars)

	# goodchars.remove(0x2) # Uncommend if you need to filter extra badchars

	# ...


'''
-------------------------------------------------------------------------------------------------------

	Contains required three sub operation for one byte.

	If carry is set to True, next byte must be decreased by 1.
	
-------------------------------------------------------------------------------------------------------
'''
class ByteSubCombination:
	def __init__(self, first, second, third, carry):
		self.first = first
		self.second = second
		self.third = third
		self.carry = carry



'''
-------------------------------------------------------------------------------------------------------

	Encoder Object

-------------------------------------------------------------------------------------------------------
'''
class Encoder:

	def __init__(self, instruction_prefix, assembly_prefix):
		self.instruction_prefix = instruction_prefix
		self.assembly_prefix = assembly_prefix


	def get_row_value(self, row, encoded=False):
		value = ""
		for col in row:
			value += "{:02x}".format(col)

		if encoded:
			value = bytearr_to_bytestr(struct.pack('<I', int(value, 16))) # 0x???????? (Little Endian)

		return value


	def to_raw(self):
		template = ""

		for row in self.matrice:
			template += f"{self.instruction_prefix}{self.get_row_value(row, True)}"			

		return template


	def comment_instruction(self, instruction, comment):
		instruction = "\"{}\"".format(instruction).ljust(22, " ")
		return f"{argv.python_var_name} += b{instruction} # {comment}\n"


	def to_commented_python(self):
		template = ""

		for row in self.matrice:
			value = self.get_row_value(row)
			
			template += self.comment_instruction(f"{self.instruction_prefix}{self.get_row_value(row, True)}", f"{self.assembly_prefix}{value}")

		return template	


'''
-------------------------------------------------------------------------------------------------------

	Zero EAX Register with and operations object

	inherit from Encoder Object

-------------------------------------------------------------------------------------------------------
'''
class EncodeZeroEax(Encoder):

	def __init__(self):	
		super().__init__(_asm_and, "and eax, 0x")
		###

		self.matrice = np.array(
									[
										[0, 0, 0, 0],
										[0, 0, 0, 0],										
									]
								)

		self.generate()


	def generate(self):
		for i in range(4):
			generate_goodchars() # add some randomness

			for first in goodchars:
				for second in goodchars:
					if (first & second) == 0:
						self.matrice[0][i] = first
						self.matrice[1][i] = second



'''
-------------------------------------------------------------------------------------------------------

	Instruction Candidate Object (4 Bytes length)

	inherit from Encoder Object
	
-------------------------------------------------------------------------------------------------------
'''
class EncodeInstruction(Encoder):

	def __init__(self, opcode, zero_eax_from_esi=False):
		super().__init__(_asm_sub, "sub eax, 0x")
		###		

		self.opcode = opcode
		self.opcode_int = int.from_bytes(opcode, "little", signed=False)
		self.complement = (0xffffffff - int(self.opcode_int) + 1)

		self.zero_eax = None
		if not zero_eax_from_esi:
			self.zero_eax = EncodeZeroEax()

		self.matrice = np.array(
									[
										[0, 0, 0, 0],
										[0, 0, 0, 0],
										[0, 0, 0, 0],			
									]
								)	

		if not self.generate():
			raise Exception("Sub Encoding Error, complement:{}".format(hex(self.complement)))	


	def to_commented_python(self):		
		template = ""
		if self.zero_eax:
			template += self.zero_eax.to_commented_python()			

			template += self.comment_instruction(_asm_push_eax, "push eax")
			template += self.comment_instruction(_asm_pop_ebx, "pop ebx")
		else:			
			template += self.comment_instruction(_asm_push_ebx, "push ebx")
			template += self.comment_instruction(_asm_pop_eax, "pop eax")
		
		template += super(EncodeInstruction, self).to_commented_python()
		
		template += self.comment_instruction(_asm_push_eax, "push eax")

		return template
		

	def validate(self):		
		i = 0x0 # EAX is expected be be eq to 0x00000000

		for row in self.matrice:
			i-= int(self.get_row_value(row), 16)

		i &= 0xffffffff

		return i == self.opcode_int


	def to_raw(self):
		template = ""

		if self.zero_eax:
			template += self.zero_eax.to_raw()

			template += _asm_push_eax
			template += _asm_pop_ebx
		else:
			template += _asm_push_ebx
			template += _asm_pop_eax


		template += super(EncodeInstruction, self).to_raw()

		template += _asm_push_eax

		return template


	"""
		`Bruteforce` possible combination of sub instruction to form back our complement.

		@value: the byte to sub encode
		@apply_carry: Apply a carry (-1) to the biggest chunk.

		Notice: a carry is applied if:
					- current byte to sub encode is equal to 0 (it become 0x100)
					- current byte to sub encode is less or equal to 2 (it becomes 0x100 + value)
	"""
	def sub_encode(self, value, prev_result):
		carry = (value == 0) or (value <= 2)
		if carry:			
			value += 0x100

		generate_goodchars() # create randomness in our encoding

		# Start from LSB to MSB	(To support correctly "carry")
		for first in goodchars:
			for second in goodchars:
				for third in goodchars:
					if value == (first + second + third):
						if prev_result and prev_result.carry:						
							if first > 1:
								first -= 1
							elif second > 1:
								second -= 1
							else:
								third -= 1	

						return ByteSubCombination(first, second, third, carry)

		return None

	def generate(self):			
		result = None
		for index, value in enumerate(self.complement.to_bytes(4, "little")):
			result = self.sub_encode(value, result)
			###

			if result:
				self.matrice[0][3 - index] = result.first
				self.matrice[1][3 - index] = result.second
				self.matrice[2][3 - index] = result.third	
			else:		
				return False

		return True	
	

'''
-------------------------------------------------------------------------------------------------------

	Entry Point
	
-------------------------------------------------------------------------------------------------------
'''
if __name__ == "__main__":

	#
	# Parse Arguments
	#
	supported_output_format = [
								"python_commented",
							    "python",
							    "c",
							    "string",
							    "hex",
							    "raw",
	]

	argument_parser = argparse.ArgumentParser(description=f"Yet another Shellcode Sub Encoder by {tcolors.blue}@DarkCoderSc{tcolors.clear}")

	argument_parser.add_argument('-s', '--shellcode', type=str, dest="shellcode", action="store", required=True,
									 help=f"Shellcode in C style format. Place payload between double quotes. Example: \"{tcolors.blue}\\x01\\x02\\x03\\x04\\x05\\x06...\\x0a{tcolors.clear}\"")

	argument_parser.add_argument('-n', '--name', type=str, dest="python_var_name", default="encoded_shellcode", action="store", required=False, 
									help="Define the variable name when exporting encoded shellcode as python or c formated variable.")

	argument_parser.add_argument('-f', '--format', type=str, dest="output_format", default="python_commented", action="store", required=False, 
									help=f"Define output format of encoded shellcode. (\"{', '.join(supported_output_format)}\")")	

	argument_parser.add_argument('-v', '--verbose', dest="verbose", default=False, action="store_true", required=False, help="Enable verbosity (always disabled on output raw format).")

	try:
		argv = argument_parser.parse_args()		
	except IOError:
		parser.error()


	#
	# Translate payload from python byte array string to byte array
	#

	try:
		bytes_to_encode = bytestr_to_bytearr(argv.shellcode)
	except:
		error("Malformed instructions. Please check help for expected format.")

		sys.exit(1)

	#
	# Check output format value
	#
	argv.output_format = argv.output_format.lower()
	if not argv.output_format in supported_output_format:
		error(f"Invalid output format value. (Supported: \"{', '.join(supported_output_format)}\")")

		sys.exit(2)

	raw_output = (argv.output_format == supported_output_format[5]) # if we are using output raw, we don't verbose anything else than encoded shellcode to stdout

	success(f"Payload successfully loaded=[{argv.shellcode}]")

	#
	# Align payload (requires to be a multiple of 4)
	#

	align_delta = (len(bytes_to_encode) % 4)
	if (align_delta > 0):
		debug("Payload requires alignement of {} bytes".format((4 - align_delta)))

		for i in range((4 - align_delta)):
			bytes_to_encode.append(0x90) # align with extra NOP's
	else:
		debug("No alignement needed.")	


	#
	# Split payload in chunk of 4 bytes
	#

	encoded_instruction = []	
	first = True
	for i in reversed(range(0, len(bytes_to_encode), 4)):		
		instruction_chunk = bytes(bytes_to_encode[i:(i+4)])
		try:								
			debug(f"Attempt to sub encode instruction=[{tcolors.blue}0x{instruction_chunk.hex()}{tcolors.clear}]...")
			
			instruction = EncodeInstruction(instruction_chunk, not first)
			first = False

			success(f"Candidate successfully sub encoded.")	
	
			debug(f"Verify if sub encoding instructions result in original instruction...")	

			if instruction.validate():
				success("Verification succeed!")
			else:
				raise Exception("Verification failed")

			encoded_instruction.append(instruction)
		except Exception as e:
			error(f"FATAL: Could not sub encode instructions. Instruction=[{instruction_chunk}] Msg=[{str(e)}]")


	if len(encoded_instruction) > 0:
		opcode = ""
		commented_python = ""
		for instruction in encoded_instruction:			
			commented_python += instruction.to_commented_python() + "\n"
			opcode += instruction.to_raw()

		raw = opcode.replace("\\x", "")

		if not raw_output:		
			if argv.output_format == supported_output_format[0]:
				title("Commented Python")
				print(commented_python.rstrip())
			elif argv.output_format == supported_output_format[1]:
				output = f"{argv.python_var_name} = b\"\"\n"
				for chunk in wrap(opcode, 64):
					output += f"{argv.python_var_name} += b\"{chunk}\"\n"

				title("Python")
				print(output.rstrip())
			elif argv.output_format == supported_output_format[2]:
				title("C / CPP")
				output = f"unsigned char {argv.python_var_name}[] = \\\n"
				for chunk in wrap(opcode, 64):
					output += f"\t\"{chunk}\"\n"
				output = output[:-1] + ";"

				print(output)
			elif argv.output_format == supported_output_format[3]:
				title("String (C / Cpp / Python etc...)")
				print(opcode)
			elif argv.output_format == supported_output_format[4]:
				title("Hex string")
				print(raw)
					

			old_len = len(bytes_to_encode)
			new_len = int(len(raw) / 2)

			title(f"{tcolors.green}Informations{tcolors.clear}")

			debug(f"Original Payload Length: {tcolors.blue}{old_len}{tcolors.clear} bytes.")
			debug(f"Encoded Payload Length: {tcolors.blue}{new_len}{tcolors.clear} bytes (+{tcolors.blue}{int((new_len * 100) / old_len)}%{tcolors.clear}).")
			debug(f"Required stack space for decoding: {tcolors.blue}{len(bytes_to_encode)}{tcolors.clear} bytes.\n")
		else:
			sys.stdout.buffer.write(bytearray.fromhex(raw))
