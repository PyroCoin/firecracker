from ecdsa import SigningKey
from flask import Flask, redirect, request

app = Flask(__name__)


@app.before_request
def before_request():
    if request.url.startswith('https://'):
        url = request.url.replace('https://', 'http://', 1)
        code = 301
        return redirect(url, code=code)


@app.route('/', methods=['GET'])
def generate_keypair():
    sk = SigningKey.generate()

    return f"""
        <p><b>Public Key:</b> {sk.to_string().hex()}</p>
        <p><b>Private Key:</b> {sk.verifying_key.to_string().hex()}</p>
        """


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
