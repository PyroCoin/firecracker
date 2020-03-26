from json import dumps

from ecdsa import SigningKey
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey
from ellipticcurve.privateKey import PublicKey
import codecs
import ecdsa


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--privateKey', default="0", type=str, help='private key')
    parser.add_argument('-m', '--message', default="0", type=str, help='message to sign')
    args = parser.parse_args()
    sk = SigningKey.from_string(bytes.fromhex(args.privateKey))

    print(sk.sign(str.encode(args.message)).hex())


