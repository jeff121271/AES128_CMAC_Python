#########################################################
##    cmac_support.py                                  ##
##                                                     ##
##    Contains a function that uses the AES CMAC       ##
##    algorithm to calculate the MAC of a message.     ##
##                                                     ##
##    Author: Jeff Campbell                            ##
##    Date  : 24 August 2016                           ##
#########################################################

import binascii
from struct import pack, unpack
from Crypto.Cipher import AES

# This is a test, should only show up
# in the change branch.

# pad_128
# Pads a block to 128 bits.
#   A (bytes) = Block to pad
#
# Returns the padded block (bytes)
def pad_128(A):
     padLen = 16 - len(A)                           # Calculate deficit
     aString = binascii.hexlify(A).decode('utf-8')  # Convert to string (just because string concatenation is easier)
     aString = aString + '80' + '00' * (padLen - 1) # Pad with 0b100...0 (0x8000...0)
     return binascii.unhexlify(aString)             # Convert back to bytes and return result

# xor_128
# XOR's two 128-bit values.
#   A (bytes) = First value
#   B (bytes) = Second value
#
# Returns the XOR result (bytes)
def xor_128(A, B):
     # Unpack into 64-bit values
     aHigh = unpack('>Q', A[:8])[0]
     aLow = unpack('>Q', A[8:])[0]
     bHigh = unpack('>Q', B[:8])[0]
     bLow = unpack('>Q', B[8:])[0]

     # Calculate XOR
     resHigh = aHigh ^ bHigh
     resLow = aLow ^ bLow
     return pack('>QQ', resHigh, resLow)

# generate_subkeys
# Returns a tuple of k1 and k2, used in CMAC algorithm.
#   key (bytes) = Key used to generate k1 and k2
#
# Returns tuple of (k1, k2) (bytes, bytes)
def generate_subkeys(key):
     const_c = binascii.unhexlify('00' * 15 + '87')    # Magic number, don't worry about it.
     const_cLow = unpack('>Q', const_c[8:])[0]
     const_zero = binascii.unhexlify('00' * 16)        # 128 bits of zero in all its glory
     const_max = binascii.unhexlify('ff' * 16)         # 128 bits of all F's
     const_max16 = unpack('>Q', const_max[:8])[0]
     aesObj = AES.new(key, AES.MODE_ECB)

     # 1. Generate k0 = E_k(0)
     k0 = aesObj.encrypt(const_zero)
     k0High = unpack('>Q', k0[:8])[0]
     k0Low = unpack('>Q', k0[8:])[0]

     # 2. k1 = k0 << 1
     k1High = ((k0High << 1) | (k0Low >> 63)) & const_max16
     k1Low = (k0Low << 1) & const_max16

     # ...and if msb(k0) was 1, k1 = (k0 << 1) XOR C
     if (k0High >> 63):
          k1Low ^= const_cLow

     # 3. Ditto K2 with K1.
     k2High = ((k1High << 1) | (k1Low >> 63)) & const_max16
     k2Low = (k1Low << 1) & const_max16
     if (k1High >> 63):
          k2Low ^= const_cLow

     # 4. Return results.
     k1 = pack('>QQ', k1High, k1Low)
     k2 = pack('>QQ', k2High, k2Low)
     return (k1, k2)

# calculate_cmac
# Implements the AES CMAC algorithm.
#   msgBytes (bytes)  = The message over which to generate the MAC
#   keyBytes (bytes)  = The key to use
#   msgLength (bytes) = The number of bytes to process
#
# Returns the 128-bit MAC (bytes)
def calculate_cmac(msgBytes, keyBytes, msgLength):

     M = msgBytes[:msgLength]

     # Start by calculating subkeys
     (k1, k2) = generate_subkeys(keyBytes)
     aesObj = AES.new(keyBytes, AES.MODE_ECB)

     # Comments starting with numbers indicate official algorithm instructions
     # 1. Divide M into n b-bit blocks, m0, m1, ..., m_n
     n = int(len(M) / 16)

     # flag indicates whether M_n is a complete block or not
     if n == 0:
          n = 1
          flag = False
     else:
          if (msgLength % 16) == 0:
               flag = True
          else:
               n += 1
               flag = False
     M_n = M[(n-1)*16:] # Get last block

     # 2. If M_n is complete then M_n = k1 XOR M_n, else M_n = k2 XOR ( PAD(M_n) )
     if flag is True:
          M_last = xor_128(M_n, k1)
     else:
          M_last = xor_128(pad_128(M_n), k2)

     # 3. Let c0 = 0
     temp = binascii.unhexlify('00' * 16)

     # 4. For i = 1, ..., i = n - 1, calculate c_i = E_k(c_i-1 XOR m_i)
     for i in range(n - 1):
          M_i = M[(i * 16):][:16]  # Clever.
          y = xor_128(temp, M_i)
          temp = aesObj.encrypt(y)

     # 5. c_n = E_k(c_n-1 XOR M_n)
     y = xor_128(M_last, temp)
     result = aesObj.encrypt(y)

     # 6. Return output.
     return result
