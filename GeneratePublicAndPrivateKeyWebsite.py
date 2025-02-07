from ecdsa import SigningKey, SECP256k1
from flask import Flask

app = Flask(__name__)


@app.route('/pyrocoinkeygen', methods=['GET'])
def generate_keypair():
    sk = SigningKey.generate(curve=SECP256k1)

    pub_key = "04" + sk.verifying_key.to_string().hex()

    return f"""
        <p><b>Public Key:</b> {pub_key}</p>
        <p><b>Private Key:</b> {sk.to_string().hex()}</p>
        <br>
        <button onClick="window.location.reload();">Generate Another Key Pair</button>
        """


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
