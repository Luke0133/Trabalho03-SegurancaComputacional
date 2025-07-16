from cryptography.hazmat.primitives import hashes
import base64
import math
import secrets
from bitarray import bitarray

HLEN = 64
SLEN = HLEN
EMBITS = 8 * HLEN + 8 * SLEN + 9   # = 1033

def main():
    file_path = input("Arquivo: ")
    with open(file_path,'rb') as f:
        data = f.read()

    result = pss_encode(data)

    #print(result.hex())
    print(base64.b64encode(result).decode())
    print()
    print(pss_verify(data, result))



"""
PSS-ENCODE -> Follows PSS encoding from RFC8017 (Section 9.1 - EMSA-PSS)
Operation for encoding data into PSS EMSA-PSS format
- Returns the Encoded Message
"""
def pss_encode(data):
    # Calculating Hash (using SHA3-512 from cryptography library)
    # hLen = 64 (bytes)
    digest = hashes.Hash(hashes.SHA3_512())
    digest.update(data)
    mHash = bytearray(digest.finalize())  
    
    emLen = math.ceil(EMBITS/8) 

    # Generates a random octet of len SLEN (in this case, generates a random number of SLEN*8 bits)
    saltBits = secrets.randbits(SLEN*8)
    salt = bytearray(saltBits.to_bytes(SLEN, byteorder = 'big'))

    # M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    mPrime = bytearray(8) + mHash + salt 

    # H = Hash(M')
    digest = hashes.Hash(hashes.SHA3_512())
    digest.update(mPrime)
    h = bytearray(digest.finalize())     

    # Generate an octet string PS consisting of (emLen - sLen - hLen - 2) zero octets
    ps = bytearray(emLen - HLEN - SLEN - 2)

    # DB = PS || 0x01 || salt, DB has length (emLen - hLen - 1)
    db = ps + bytearray([1]) + salt

    dbMask = mgf1(h, (emLen - HLEN - 1))

    # maskedDB = DB \xor dbMask.
    maskedDB = bytearray(a ^ b for a, b in zip(db, dbMask))

    # Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero
    bits_to_clear = emLen * 8 - EMBITS 
    if bits_to_clear > 0:
        mask = (1 << (8 - bits_to_clear)) - 1
        maskedDB[0] = maskedDB[0] & mask

    # EM = maskedDB || H || 0xbc
    em = maskedDB + h + bytearray([0xbc])

    return em

"""
PSS-VERIFY -> Follows PSS verification process from RFC8017 (Section 9.1 - EMSA-PSS)
Operation for checking if the received PSS EMSA-PSS data is valid for a given data
- Returns True if consistent, otherwise returns False
"""
def pss_verify(data, em):
    emLen = len(em)

    # Calculating Hash (using SHA3-512 from cryptography library)
    # hLen = 64 (bytes)
    digest = hashes.Hash(hashes.SHA3_512())
    digest.update(data)
    mHash = bytearray(digest.finalize())  
    
    if emLen < (HLEN + SLEN + 2): return False
    if em[-1] != 0xBC: return False

    # maskedDB are the leftmost emLen - hLen - 1 octets of EM and H are the next hLen octets
    maskedDB = em[:(emLen - HLEN - 1)]
    h = em[(emLen - HLEN - 1):(emLen - 1)]

    # Checks if the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB are all equal to zero
    bits_to_check = 8 * emLen - EMBITS
    if bits_to_check > 0:
        if bits_to_check > 0:
            mask = 0xFF << (8 - bits_to_check) & 0xFF   # Mask for the leftmost bits (that need to be zero)
            if maskedDB[0] & mask != 0: return False    # so, if the result isn't zero, it means there's an inconsistency

    # DB = maskedDB \xor dbMask.
    dbMask = mgf1(h, (emLen - HLEN - 1))
    db = bytearray(a ^ b for a, b in zip(maskedDB, dbMask))

    # Set the leftmost 8emLen - emBits bits of the leftmost octet in db to zero
    bits_to_clear = emLen * 8 - EMBITS 
    if bits_to_clear > 0:
        mask = (1 << (8 - bits_to_clear)) - 1
        db[0] = db[0] & mask

    # Checks if PS exists (emLen - HLEN - SLEN - 2 octets of 0)
    ps_len = emLen - HLEN - SLEN - 2
    if any(b != 0 for b in db[:ps_len]): return False

    # And if the next octet is 0x01
    if db[ps_len] != 0x01: return False

    # Gets the salt
    salt = db[(ps_len + 1):] 

    # Let  M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    mPrime = bytearray(8) + mHash + salt
   
    # H' = Hash(M')
    digest = hashes.Hash(hashes.SHA3_512())
    digest.update(mPrime)
    hPrime = bytearray(digest.finalize())  

    # If H = H', it's consistent. Otherwise, it's inconsistent
    return True if h == hPrime else False

"""
MGF1 - Mask Generation Function based on Hash Function
(Described on section B.2)
"""
def mgf1(mgfSeed, maskLen):
    t = bytearray()
    loop = math.ceil(maskLen/HLEN)

    for i in range(loop):
        # Converts counter to an octet string C of length 4 octets
        c = i.to_bytes(4, byteorder='big')

        # Hash of the seed mgfSeed and C
        digest = hashes.Hash(hashes.SHA3_512())
        digest.update(mgfSeed + c)
        hashMGF = bytearray(digest.finalize()) 

        # T = T || Hash(mgfSeed || C)
        t = t + hashMGF

    return t[:maskLen]


main()