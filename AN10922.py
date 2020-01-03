from Crypto.Cipher import AES
from Crypto.Cipher import DES3
import struct
import codecs

def hexdecode(string):
	return codecs.decode( string, "hex" )

def hexencode(bytestr):
	return codecs.encode(  bytestr, "hex" )

def bitshift_aes(input):
	preout=[]
	for i in range(0,16):
		a = input[i]
		if i==15:
			b = input[0]
			preout.append(((a<<1)^((0-(b>>7))&0x87))%256)
		else:
			b = input[i+1]
			preout.append(((a<<1)|(b>>7))%256)
	return struct.pack('BBBBBBBBBBBBBBBB',preout[0],preout[1],preout[2],preout[3],preout[4],preout[5],preout[6],preout[7],preout[8],preout[9],preout[10],preout[11],preout[12],preout[13],preout[14],preout[15])

def bitshift_des(input):
	preout=[]
	for i in range(0,8):
		a = input[i]
		if i==7:
			b = input[0]
			preout.append(((a<<1)^((0-(b>>7))&0x1B))%256)
		else:
			b = input[i+1]
			preout.append(((a<<1)|(b>>7))%256)
	return struct.pack('BBBBBBBB',preout[0],preout[1],preout[2],preout[3],preout[4],preout[5],preout[6],preout[7])

def xor_aes(target,subkey):
	preout=[]
	index=0
	for i in range(0,16):
		a = target[i]
		b = subkey[i]
		preout.append((a^b)%256)
	return struct.pack('BBBBBBBBBBBBBBBB',preout[0],preout[1],preout[2],preout[3],preout[4],preout[5],preout[6],preout[7],preout[8],preout[9],preout[10],preout[11],preout[12],preout[13],preout[14],preout[15])

def xor_des(target,subkey):
	preout=[]
	index=0
	for i in range(0,8):
		a = target[i]
		b = subkey[i]
		preout.append((a^b)%256)
	return struct.pack('BBBBBBBB',preout[0],preout[1],preout[2],preout[3],preout[4],preout[5],preout[6],preout[7])

def prepare_input_aes(subkeys,divinput,divconst):
	divadded=bytearray(bytes(divconst, "utf-8"))
	divadded.extend( divinput )
	padded=0
	for i in range(len(divadded)-1,31):
		if padded==0:
			padded=1
			divadded.extend(b'\x80')
		else:
			divadded.extend(b'\x00')
	xored=divadded[0:16]
	xored=xored+(xor_aes(divadded[16:32],subkeys[padded+1]))
	return xored

def prepare_input_des(subkeys,divinput,divconst):
	divadded=bytearray(bytes(divconst, "utf-8"))
	divadded.extend( divinput )
	padded=0
	for i in range(len(divadded)-1,15):
		if padded==0:
			padded=1
			divadded.extend(b'\x80')
		else:
			divadded.extend(b'\x00')
	xored=divadded[0:8]
	xored=xored+(xor_des(divadded[8:16],subkeys[padded+1]))
	return xored

def generate_subkeys_aes(bin_masterkey):
	subkeys={}
	cipher=AES.new(bin_masterkey, AES.MODE_CBC,b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	subkeys[0]=cipher.encrypt(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	subkeys[1]=bitshift_aes(subkeys[0])
	subkeys[2]=bitshift_aes(subkeys[1])
	return subkeys

def generate_subkeys_des(bin_masterkey):
	subkeys={}
	cipher=DES3.new(bin_masterkey, DES3.MODE_CBC,b"\x00\x00\x00\x00\x00\x00\x00\x00")
	subkeys[0]=cipher.encrypt(b"\x00\x00\x00\x00\x00\x00\x00\x00")
	subkeys[1]=bitshift_des(subkeys[0])
	subkeys[2]=bitshift_des(subkeys[1])
	return subkeys

def encrypt_aes(bin_masterkey,input):
	cipher=AES.new(bin_masterkey, AES.MODE_CBC,b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	return cipher.encrypt(input)

def encrypt_des(bin_masterkey,input):
	cipher=DES3.new(bin_masterkey, DES3.MODE_CBC,b"\x00\x00\x00\x00\x00\x00\x00\x00")
	return cipher.encrypt(input)

def restore_version_des(divoutput,version):
	preout=[]
	myversion = version%256
	for i in range(0,8):
		unpacked = divoutput[i]
		mybit = ( myversion >> (7-i) ) & 1
		preout.append( (unpacked&254) | mybit )
	changed = struct.pack('BBBBBBBB',preout[0],preout[1],preout[2],preout[3],preout[4],preout[5],preout[6],preout[7])
	return changed + divoutput[8:]

#Masterkey length 16 Byte (128 bit), Diversification input length 1-31 Bytes, Output 24 Byte
def diversify_aes128(masterkey,divinput):
	subkeys = generate_subkeys_aes(masterkey)
	input = prepare_input_aes(subkeys,divinput,"\x01")
	return encrypt_aes(masterkey,input)[16:32]

#Masterkey length 24 Byte (192 bit), Diversification input length 1-31 Bytes, Output 24 Byte
def diversify_aes192(masterkey,divinput):
	subkeys = generate_subkeys_aes(masterkey)
	inputd1 = prepare_input_aes(subkeys,divinput,"\x11")
	inputd2 = prepare_input_aes(subkeys,divinput,"\x12")
	derivedA = encrypt_aes(masterkey,inputd1)
	derivedB = encrypt_aes(masterkey,inputd2)
	midpart = xor_des(derivedA[24:32], derivedB[16:24])
	return derivedA[16:24] + midpart + derivedB[24:32]

#Masterkey length 32 Byte (256 bit), Diversification input length 1-31 Bytes, Output 32 Byte
def diversify_aes256(masterkey,divinput):
	subkeys = generate_subkeys_aes(masterkey)
	inputd1 = prepare_input_aes(subkeys,divinput,"\x41")
	inputd2 = prepare_input_aes(subkeys,divinput,"\x42")
	derivedA = encrypt_aes(masterkey,inputd1)
	derivedB = encrypt_aes(masterkey,inputd2)
	return derivedA[16:32] + derivedB[16:32]

#Masterkey length 16 Byte (128 bit), Diversification input length 1-15 Bytes, Output 16 Byte
def diversify_2tdea_norestore(masterkey,divinput):
	subkeys = generate_subkeys_des(masterkey)
	inputd1 = prepare_input_des(subkeys,divinput,"\x21")
	inputd2 = prepare_input_des(subkeys,divinput,"\x22")
	derived1 = encrypt_des(masterkey,inputd1)
	derived2 = encrypt_des(masterkey,inputd2)
	return derived1[8:16] + derived2[8:16]

#Same as diversify_2tdea_norestore, but restores version of masterkey
def diversify_2tdea_versionrestore(masterkey,divinput,version):
	return restore_version_des( diversify_2tdea_norestore( masterkey, divinput ), version )

#Masterkey length 24 Byte (192 bit), Diversification input length 1-15 Bytes, Output 24 Byte
def diversify_3tdea_norestore(masterkey,divinput):
	subkeys = generate_subkeys_des(masterkey)
	inputd1 = prepare_input_des(subkeys,divinput,"\x31")
	inputd2 = prepare_input_des(subkeys,divinput,"\x32")
	inputd3 = prepare_input_des(subkeys,divinput,"\x33")
	derived1 = encrypt_des(masterkey,inputd1)
	derived2 = encrypt_des(masterkey,inputd2)
	derived3 = encrypt_des(masterkey,inputd3)
	return derived1[8:16] + derived2[8:16] + derived3[8:16]

#Same as diversify_3tdea_norestore, but restores version of masterkey
def diversify_3tdea_versionrestore(masterkey,divinput,version):
	return restore_version_des( diversify_3tdea_norestore( masterkey, divinput ), version )

def test():
	target1 = hexdecode("A8DD63A3B89D54B37CA802473FDA9175")
	target2 = hexdecode("ce39c8e1cd82d9a7bedbe9d74af59b23176755ee7586e12c")
	target3 = hexdecode("16F9587D9E8910C96B9648D006107DD7")
	target4 = hexdecode("2E0DD03774D3FA9B5705AB0BDA91CA0B55B8E07FCDBF10EC")
	target5 = hexdecode("4FC6EEC820B4C54314990B8611662DB695E7880982C0001E6067488346100AED")

	out1 = diversify_aes128( hexdecode("00112233445566778899AABBCCDDEEFF"), hexdecode("04782E21801D803042F54E585020416275") )
	out2 = diversify_aes192( hexdecode("00112233445566778899AABBCCDDEEFF0102030405060708"), hexdecode("04782E21801D803042F54E585020416275") )
	out3 = diversify_2tdea_versionrestore( hexdecode("00112233445566778899AABBCCDDEEFF"), hexdecode("04782E21801D803042F54E58502041"), 0x55 )
	out4 = diversify_3tdea_versionrestore( hexdecode("00112233445566778899AABBCCDDEEFF0102030405060708"), hexdecode("04782E21801D803042F54E5850"), 0x55 )
	out5 = diversify_aes256( hexdecode("00112233445566778899AABBCCDDEEFF0102030405060708090A0B0C0D0E0F00"), hexdecode("04782E21801D803042F54E585020416275") )
	failed = 0
	if not target1==out1:
		failed = failed + 1
		print( "AES-128 test failed", hexencode(out1), hexencode(target1) )
	if not target2==out2:
		failed = failed + 1
		print( "AES-192 test failed", hexencode(out2), hexencode(target2) )
	if not target3==out3:
		failed = failed + 1
		print( "2TDEA test failed", hexencode(out3), hexencode(target3) )
	if not target4==out4:
		failed = failed + 1
		print( "3TDEA test failed", hexencode(out4), hexencode(target4) )
	if not target5==out5:
		failed = failed + 1
		print( "AES-256 test failed", hexencode(out5), hexencode(target5) )
	
	if failed==0:
		print( "All tests successful!" )
	return failed

def cli_pgm():
	if len( sys.argv ) == 2 and sys.argv[1] == "test":
		return test()

	if len( sys.argv ) < 4 or len( sys.argv ) > 5:
		print( "Usage: " + sys.argv[0] + " <algorithm> <masterkey> <divinput> (<version>)" )
		print( "\t<algorithm>, available: aes128, aes192, aes256, 2tdea, 3tdea" )
		print( "\t<masterkey>, hex-string of masterkey, must be 16 byte (aes128,2tdea) or 24 byte (aes192,3tdea) or 32 byte (aes256)" )
		print( "\t<divinput>, hex-string of diversification input, must be 1..31 (aes128,aes192,aes256) or 1..15 (2tdea,3tdea)" )
		print( "\t<version>, version number of masterkey, optional, only 2tdea/3tdea" )
		print( "Diversification input usually consists of PICC UID (7 Byte) + App ID (3 Byte) + ASCII System Identifier (variable length)" )
		print( "For more information consult AN10922 (https://www.nxp.com/docs/en/application-note/AN10922.pdf)" )
		return 1

	if sys.argv[1] == 'aes128':
		print( hexencode( diversify_aes128( hexdecode(sys.argv[2]), hexdecode(sys.argv[3]) ) ) )
	elif sys.argv[1] == 'aes192':
		print( hexencode( diversify_aes192( hexdecode(sys.argv[2]), hexdecode(sys.argv[3]) ) ) )
	elif sys.argv[1] == 'aes256':
		print( hexencode( diversify_aes256( hexdecode(sys.argv[2]), hexdecode(sys.argv[3]) ) ) )
	elif sys.argv[1] == '2tdea' and len(sys.argv) == 5:
		print( hexencode( diversify_2tdea_versionrestore( hexdecode(sys.argv[2]), hexdecode(sys.argv[3]), int(sys.argv[4]) ) ) )
	elif sys.argv[1] == '3tdea' and len(sys.argv) == 5:
		print( hexencode( diversify_2tdea_versionrestore( hexdecode(sys.argv[2]), hexdecode(sys.argv[3]), int(sys.argv[4]) ) ) )
	elif sys.argv[1] == '2tdea' and len(sys.argv) == 4:
		print( hexencode( diversify_2tdea_norestore( hexdecode(sys.argv[2]), hexdecode(sys.argv[3]) ) ) )
	elif sys.argv[1] == '3tdea' and len(sys.argv) == 4:
		print( hexencode( diversify_3tdea_norestore( hexdecode(sys.argv[2]), hexdecode(sys.argv[3]) ) ) )
	else:
		print( "Algorithm not found!" )
		return 1
	return 0

if __name__ == "__main__":
	import sys
	exit(cli_pgm())
