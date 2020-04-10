from json import dumps
import hashlib
from ecdsa import SigningKey, SECP256k1
import json
import binascii

    
def Verify(private):
    sk = SigningKey.from_string(private, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    PublicKey = '04' + binascii.hexlify(vk.to_string()).decode()

    return PublicKey
    


def CreateSignature(senderPrivateKey, sender, recipient, amount):
    senderPrivateKey.replace(' ', '')
    sender.replace(' ', '')
    recipient.replace(' ', '')
    amount.replace(' ', '')
    HashedPrivateKey = str(hashlib.sha256(senderPrivateKey.encode()).hexdigest())

    PublicConfirm = Verify(senderPrivateKey)

    
    sender = SigningKey.from_string(bytes.fromhex(sender), curve=SECP256k1)
    s_pub_key = sender.get_verifying_key().to_string().hex()



    r_pub_key = recipient
    transaction = {'sender': s_pub_key, 'recipient': r_pub_key, 'amount': amount,
                    'signature': sender.sign(f"{s_pub_key} -{amount}-> {r_pub_key}".encode()).hex()}

                
    return sender.sign(f"{s_pub_key} -{amount}-> {r_pub_key}".encode()).hex()




