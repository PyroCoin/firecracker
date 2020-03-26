from ecdsa import SigningKey

if __name__ == '__main__':
    sk = SigningKey.generate()
    print(f"Private Key: {sk.to_string().hex()}")
    print(f"Public Key: {sk.get_verifying_key().to_string().hex()}")
