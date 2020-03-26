from json import dumps

from ecdsa import SigningKey
import json

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-s', '--sender', default="ignore", type=str, help="sender private key")
    parser.add_argument('-r', '--recipient', default="ignore", type=str, help='recipient public key')
    parser.add_argument('-a', '--amount', default=200, type=int, help='amount to send')

    args = parser.parse_args()

    if args.sender != "ignore":
        sender = SigningKey.from_string(bytes.fromhex(args.sender))
        s_pub_key = sender.get_verifying_key().to_string().hex()
    else:
        sender = SigningKey.generate()
        s_pub_key = sender.get_verifying_key().to_string().hex()

    if args.recipient != "ignore":
        r_pub_key = recipient = args.recipient
    else:
        recipient = SigningKey.generate()
        r_pub_key = recipient.get_verifying_key().to_string().hex()

    transaction = {'sender': s_pub_key, 'recipient': r_pub_key, 'amount': args.amount,
                   'signature': sender.sign(f"{s_pub_key} -{args.amount}-> {r_pub_key}".encode()).hex()}
    print(json.dumps(transaction))
