from json import dumps
import hashlib
from ecdsa import SigningKey, SECP256k1
import json

    



def CreateSignature(senderPrivateKey, sender, recipient, amount):
    senderPrivateKey.replace(' ', '')
    sender.replace(' ', '')
    recipient.replace(' ', '')
    amount.replace(' ', '')
    HashedPrivateKey = str(hashlib.sha256(senderPrivateKey.encode()).hexdigest())


    if HashedPrivateKey == sender:
        sender = SigningKey.from_string(bytes.fromhex(sender), curve=SECP256k1)
        s_pub_key = sender.get_verifying_key().to_string().hex()



        r_pub_key = recipient = recipient

        transaction = {'sender': s_pub_key, 'recipient': r_pub_key, 'amount': amount,
                        'signature': sender.sign(f"{s_pub_key} -{amount}-> {r_pub_key}".encode()).hex()}

                
        return sender.sign(f"{s_pub_key} -{amount}-> {r_pub_key}".encode()).hex()

    else: 
        return 'Incorrect Data'


