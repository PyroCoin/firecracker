from ecdsa import SigningKey, SECP256k1
from flask import Flask

app = Flask(__name__)


@app.route('/pyrocoinkeygen', methods=['GET'])
def generate_keypair():
    sk = SigningKey.generate(curve=SECP256k1)

    return f"""
        <p><b>Public Key:</b> {sk.verifying_key.to_string().hex()}</p>
        <p><b>Private Key:</b> {sk.to_string().hex()}</p>
        """


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
