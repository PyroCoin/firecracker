import os
import binascii

priv_key = os.urandom(32)


fullkey = '80' + binascii.hexlify(priv_key).decode()
print(priv_key)

'''sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
WIF = base58.b58encode(binascii.unhexlify(fullkey+sha256b[:8]))'''