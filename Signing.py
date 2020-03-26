from json import dumps
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey
from ellipticcurve.privateKey import PublicKey


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--privateKey', default="0", type=str, help='private key')
    parser.add_argument('-m', '--message', default="0", type=str, help='message to sign')
    args = parser.parse_args()

    privateKey = PrivateKey.fromString(str.encode("5K6sDcFgDhUDG6Teq8nKfepzwdoR7rPvunLHuDmUVHEXGum7twx"))
    message = "17xYst1wBkMxSUr4XuGUtRdXAF2h5eqSN6 -200-> 0"

    print(Ecdsa.sign(message, privateKey).toBase64())

    Ecdsa.verify("17xYst1wBkMxSUr4XuGUtRdXAF2h5eqSN6 -200-> 0", Ecdsa.sign(message, privateKey), privateKey.publicKey())