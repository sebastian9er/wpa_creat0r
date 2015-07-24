###########################################################
#                                                         #
# WPA Handshake Creator                                   #
#                                                         #
# Developed by Sebastian Neuner (if not otherwise stated) #
# sneuner@sba-research.org                                #
#                                                         #
# This is the backend of the WPA cracking exercise at     #
# TU Vienna                                               #
#                                                         #
# Called:                                                 #
# python2 wpa_creat0r.py <student-id> <password file>     #
#                                                         #
# Outfiles:                                               #
#   - A WPA handshake as CAP file with a random password  #
#     taken from the supplied password file               #
#   - A file for the teaching assistent to check if a     #
#     student has successfully broken the handshake       #
#                                                         #
# (c) 2013                                                #
#                                                         #
# License: GPL v2                                         #
#                                                         #
###########################################################

import sys
import hmac
import hashlib
from binascii import hexlify, unhexlify, a2b_hex
from struct import pack
import random
from datetime import datetime

sha = hashlib.sha1
md5 = hashlib.md5
sha256 = hashlib.sha256

if (len(sys.argv) != 3):
   sys.exit("Try it with 'python wpa_creat0r.py <student-id> <password file>'")
else:
   studentID = str(sys.argv[1])
   pwfile = str(sys.argv[2])

print "\nStarting WPA-handshake Creat0r ... \n"

######################################################
# Password based Key Derivation Function #2 (PBKDF2) #
# Thanks to Matt Johnston                            #
######################################################

def pbkdf2( password, salt, itercount, keylen, hashfn = sha ):
  try:
    # depending whether the hashfn is from hashlib or sha/md5
    digest_size = hashfn().digest_size
  except TypeError:
    digest_size = hashfn.digest_size
    
  # l - number of output blocks to produce
  l = keylen / digest_size

  if keylen % digest_size != 0:
    l += 1

  h = hmac.new( password, None, hashfn )

  T = ""
    
  for i in range(1, l+1):
    T += pbkdf2_F( h, salt, itercount, i )
      
  return T[0: keylen]


def xorstr( a, b ):
  if len(a) != len(b):
    raise "xorstr(): lengths differ"

  ret = ''
  for i in range(len(a)):
    ret += chr(ord(a[i]) ^ ord(b[i]))

  return ret


def prf( h, data ):
  hm = h.copy()
  hm.update( data )
  return hm.digest()


def pbkdf2_F( h, salt, itercount, blocknum ):
  U = prf( h, salt + pack('>i',blocknum ) )
  T = U

  for i in range(2, itercount+1):
    U = prf( h, U )
    T = xorstr( T, U )

  return T


########################################
# Custom Pseudo Randomnumber Generator #
# Thanks to user user1451340           #
########################################

def customPRF512(key, A, B):
  blen = 64
  i = 0
  R = ''
  while i<=((blen*8+159)/160):
    hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),digestmod=hashlib.sha1)
    i+=1
    R = R+hmacsha1.digest()
 
  return R[:blen]

################################################
# Get random entry from supplied password file #
################################################

def getRandomPW():
   with open(pwfile, "r") as pwf:
     lines = pwf.readlines()

   randomword = str(lines[random.randrange(1, len(lines))].replace("\n", ""))

   return randomword

#########################
# Do the Crypto         #
#########################

def blackVoodooMagic(studentid):
  ssid = "wpa2own"
  A = "Pairwise key expansion"
  APmac = a2b_hex("000b86c2a485")
  clientmac = a2b_hex("0013ce5598ef")
  ANonce = a2b_hex("579bfba6d15d24e1dbed0f45c2620927fa0f62df66c79b17001414ad08549c0f")
  SNonce = a2b_hex("e8dfa16b8769957d8249a4ec68d2b7641d3782162ef0dc37b014cc48343e8dd6")
  B = min(APmac, clientmac) + max(APmac, clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)

  # Data taken from the second 802.11 authentication packet (Introduced by 0x0103). For the MIC calculation the MIC is first filled with null bytes!
  data = a2b_hex("01030079fe010900000000000000000001e8dfa16b8769957d8249a4ec68d2b7641d3782162ef0dc37b014cc48343e8dd6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001add180050f20101000050f20201000050f20201000050f2022a00")

  # Student ID will later be concatenated with the random PW
  pmk = pbkdf2(studentid, ssid, 4096, 32)
  ptk = customPRF512(pmk, A, B)

  # The first 16 bytes of the PTK are the Key Confirmation Key (KCK). The whole PTK would be 64 byte
  mic = hmac.new(ptk[0:16], data)
   
  # HMAC MD5 for MIC calculation
  mic_printable = mic.hexdigest()
   
  return mic_printable

###################
# cap/pcap editor #
###################

# Read the cap-file that is used to manipulate
with open("pattern.cap", "rb") as infile:
  dump = infile.read()

hexdump = hexlify(dump)

# Passphrase for WPA-handshake: student-ID plus random-PW
voodoo = studentID + getRandomPW()

# Replace the MIC in the pattern.cap with the new, calculated MIC
hexdump = hexdump.replace("6d45f3538ead8eca5598c260eefe6f51", blackVoodooMagic(voodoo))

output = unhexlify(hexdump)

# Write the new cap-file to disk with the student-ID as filename
with open(studentID + ".cap", "w") as outfile:
  outfile.write(output)


####################################################################
# File for the student assistent to check if the broken passphrase #
# (by the student) is correct and if a specific student has ever   #
# downloaded a handshake                                           #
####################################################################

with open("assistent.txt", "a") as assistent:
  assistent.write("WPA handshake " + studentID + ".cap was written on " + str(datetime.now()) + " to disk.\n")
  assistent.write("The handshake belongs to " + studentID +".\n")
  assistent.write("The passphrase is: " + voodoo + "\n\n\n")
