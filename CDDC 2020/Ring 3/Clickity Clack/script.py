import sys
# https://gist.github.com/MightyPork/6da26e382a7ad91b5496ee55fdc73db2
keymap = {4: "a", 5: "b", 6: "c", 7: "d", 8: "e", 9: "f", 10: "g", 11: "h", 12: "i", 13: "j", 14: "k", 15: "l", 16: "m", 17: "n", 18: "o", 19: "p", 20: "q", 21: "r", 22: "s", 23: "t", 24: "u", 25: "v", 26: "w", 27: "x", 28: "y", 29: "z", 30: "1", 31: "2", 32: "3", 33: "4", 34: "5", 35: "6", 36: "7", 37: "8", 38: "9", 39: "0", 40: "\n", 44: " ", 45: "-", 47: "[", 48: "]", 52: "'", 54: ",", 57: "[CapsLock]", 79: "[RightArrow]", 80: "[LeftArrow]"}
usbdata = open('21.txt')
for line in usbdata:
	bytesArray = bytearray.fromhex(line[4:6])
	for byte in bytesArray:
#		if shift == '02':
#			sys.stdout.write('[Shift]')
		if byte != 0:
			keyVal = int(byte)
			if keyVal in keymap:
				if (line[0:2] == '02'):
					sys.stdout.write(keymap[keyVal].upper())
				else:
					sys.stdout.write(keymap[keyVal])
			else:
				print "No value matching: ", str(keyVal)