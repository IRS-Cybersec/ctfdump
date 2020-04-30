#!/usr/bin/env python3

from Crypto.Cipher import AES
import base64
import sys
import signal

server_secret = "Aero{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"
#server_secret = "Aero{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
KEY = 'XXXXXXXXXXXXXXXX'.encode()

banner = '''-------------------------
*** Old Crypto Server ***
-------------------------
'''

menu = '1. Encrypt\n2. Decrypt\n3. Get server secret\n4. Exit\n> '

def pad( data ):
	return data + '\x00' * ( 16 - ( len( data ) % 16 ) )

def check_key( key ):
	if len( key ) > 16:
		print( "{-} Error key len!" )
		sys.exit( -1339 )
	
	if len( key ) == 16:
		return key

	return key.ljust( 16, '\x00' )

def encrypt( msg, key ):
	key = check_key( key ).encode()
	aes = AES.new( key, AES.MODE_ECB )
	return base64.b64encode( aes.encrypt( pad( msg ).encode() ) )

def decrypt( msg, key ):
	key = check_key( key ).encode()
	aes = AES.new( key, AES.MODE_ECB )
	return aes.decrypt( msg )

def get_server_secret( msg ):
	global KEY, server_secret

	aes = AES.new( KEY, AES.MODE_ECB )
	msg += server_secret

	return base64.b64encode( aes.encrypt( pad( msg ).encode() ) )

if __name__ == "__main__":

	#signal.alarm( 3 )

	while 1:
		option = input( menu )

		if option not in [ '1','2','3','4' ]:
			print( "{-} Error option! Exit!" )
			sys.exit( -1337 )

		if option == '1':
			_key  = input( "Enter cipher key: " )
			_data = input( "Enter data: " )

			print( "{+} Encryption result: %s" % encrypt( _data, _key ) )

		elif option == '2':
			_key  = input( "Enter cipher key: " )
			_data = input( "Enter ciphertext(in base64): " )

			try:
				_data = base64.b64decode( _data.encode() )
			except:
			 	print( "{+} Some error in base64 decode!" )
			 	sys.exit( -1338 )

			print( "{+} Decryption result: %s" % decrypt( _data, _key ) )

		elif option == '3':
			salt = input( "Enter salt: " )

			print( "{+} Encrypted secret: %s" % get_server_secret( salt ) )

		elif option == '4':
			sys.exit( -1 )
