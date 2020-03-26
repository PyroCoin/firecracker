from ecdsa import SigningKey
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route('/', methods=['GET'])
def full_chain():
    sk = SigningKey.generate()

    return f"""
        <p><b>Public Key:</b> {sk.to_string().hex()}</p>
        <p><b>Private Key:</b> {sk.verifying_key.to_string().hex()}</p>
        """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
