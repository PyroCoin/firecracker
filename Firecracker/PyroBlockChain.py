import hashlib
import json
from time import time
from urllib.parse import urlparse
import requests
from ecdsa import BadSignatureError
from flask import Flask, jsonify, request
import ecdsa
from datetime import datetime


def verify_signature(signature, text, public_key):
    try:
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        try:
            vk.verify(bytes.fromhex(signature), text.encode())
            return True
        except BadSignatureError:
            return False

    except ValueError:
        return False


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.users = {'0': 250000000}
        self.verifiedTransactions = []


        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid
        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1





        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain
        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block

        This function verifies payments. Basically, it makes sure that a user is able to pay the amount that the transaction specifies
        It also moves the PyroCoin between users.

        However, when a user sends money to someone, the program automatically verifies that they can pay, before the transaction is sent.
        However, only the sender verifies it, so with this system, we have nodes verify this before creating a new block.
        If this transaction was already verified by the node, they take no action because in their chain, the money has already been transfered.
        """
        transactionList = len(self.current_transactions)
        for transactions in range(0,transactionList): #Creates a loop that goes through all of the current transactions

            TransactionDict = self.current_transactions[transactions] #Creates a variable equal to the transactions that haven't been added to a new block
            TransactionSender = TransactionDict.get('sender') #Creates a variable that is equal to the sender's public key
            TransactionReciever = TransactionDict.get('recipient') #Creates a variable that is equal to sender's public key
            TransactionAmount = TransactionDict.get('amount') #Creates a variable that is equal to the transaction amount

            if TransactionDict.get('transaction_id') in self.verifiedTransactions: #Check if the transaction has already been verified by the node
                pass #If so just skip


            else: #If this is a transaction that hasn't been verified, verify

                userWorth = self.users.get(TransactionSender) #Gets the amount of coins a user has. (Key is equal to the name of the user)
                recipientUserWorth = self.users.get(TransactionReciever) #Variable that is equal to the net worth of the reciever


                if userWorth == None: #Checks if the user has ever made a transaction/ is in the list
                    self.users[TransactionSender] = 0 #Sets the worth to 0 because the user has never made a transaction and has no money
                    userWorth = 0 #Sets the userworth to 0

                userWorth = self.users.get(TransactionSender) #Reevalutes the userworth


                if recipientUserWorth == None: #Checks if recipient has ever been involved in a transaction
                    self.users[TransactionReciever] = 0 #If the user has never been involved in a transaction, they have no money

                recipientUserWorth = self.users.get(TransactionReciever) #Reevaluates the userworth testing


                if self.current_transactions[transactions].get('amount') > userWorth: #Checks if the user can afford to pay the transaction
                    if TransactionDict.get('transaction_id')  in self.verifiedTransactions: #If this transaction has already been verified, don't change it
                        pass
                    else:
                        self.current_transactions.remove(self.current_transactions[transactions]) #If they cannot, the transaction is removed from the list of current transactions

                else:
                    if TransactionDict.get('transaction_id') in self.verifiedTransactions: #If this transaction has already been verified, don't change it
                        pass
                    else:
                        self.users[TransactionSender] -= TransactionAmount #Subtracts the amount from the sender
                        self.users[TransactionReciever] += TransactionAmount #Adds the amount from the sender





        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }



        # Reset the current list of transactions
        self.current_transactions = []
        self.verifiedTransactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block
        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount of PryoCoin sent
        :return: The index of the Block that will hold this transaction
        """

        transaction_id = str(str(sender) + str(recipient) + str(amount) + str(datetime.now()) + str(len(self.chain) + 1)).encode()
        transaction_id = hashlib.sha256(transaction_id).hexdigest()
        '''Below is the verification for payments. It essentially makes sure the sender has enough money to pay for the transaction.
        If the user does, the money will be transfered, otherwise, it will not.
        It also adds user to the user list if they have never participated in a transaction'''



        userWorth = self.users.get(sender) #Create a variable the is equal to the worth of the sender
        recipientWorth = self.users.get(recipient) #Creates a variable that is equal to the worth of the recipient

        if userWorth == None: #Checks if the sender has ever been involved in a transaction
            self.users[sender] = 0 #If not, their net worth is 0

        userWorth = self.users.get(sender) #Reevaluates the userworth

        if recipientWorth == None: #Checks if the recipient has ever been involved in a transaction
            self.users[recipient] = 0 #If not, their net worth is 0

        recipientWorth = self.users.get(recipient) #Reevaluates the recipient's userworth

        if amount > userWorth:
            pass
        else:
            self.users[sender] -= amount #Subtracts the amount from the sender
            self.users[recipient] += amount #Adds the amount from the sender
            self.current_transactions.append({
                'sender': sender,
                'recipient': recipient,
                'amount': amount,
                'transaction_id': transaction_id
            })
            self.verifiedTransactions.append(transaction_id)


        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof

        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.
        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:5] == "00000"


# Instantiate the Node
app = Flask(__name__)

# ---------------------[Routes]--------------------- #

node_public_key = 1

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_public_key,
        amount=1,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json(force=True)

    # Check that the required fields are in the POST'ed data
    required = ['signature', 'sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    unsigned_transaction_format = f"{values['sender']} -{values['amount']}-> {values['recipient']}"

    # Verify signature is valid
    if not verify_signature(values['signature'], unsigned_transaction_format, values['sender']):
        return 'Your signature does not verify your transaction', 401



    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        print("Our chain was updated and was replaced with one of a chain from one of our peer nodes")
    else:
        print("Our chain was appears to be up to date")
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/users', methods=['GET'])
def users():
    return str(blockchain.users)








if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-key', '--nodeKey', default="0", type=str, help='key for this node')
    args = parser.parse_args()
    port = args.port

    node_public_key = args.nodeKey

    if node_public_key == "0":
        raise ValueError("You must specify a node key!")


    print(node_public_key)

    app.run(host='0.0.0.0', port=port)