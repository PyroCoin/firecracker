import hashlib
import json
from time import time
from urllib.parse import urlparse
import requests
from ecdsa import BadSignatureError
from flask import Flask, jsonify, request
import ecdsa
from datetime import datetime
import threading

from Communication.DataStoring import FirebaseConnection
from Communication.appClient import main
from Communication.appServer import Server 


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
        self.transactionsCheck = []
        self.verifiedTransactions = []
        self.Transactions = {}


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


    def valid_users(self, userList, recievedUserList):
        try:
            if len(recievedUserList) > len(userList):
                

                for user in RecievedUserList:
                    if user not in userList:
                        userList.append(user)
                    else:
                        pass
            else:
                pass
        except:
            pass


    def validTransactions(self, currentTransactions, recievedTransactions):
        try:
            if len(recievedTransactions) > len(currentTransactions):
                for transaction in recievedTransactions:
                    if transaction not in currentTransactions:
                        currentTransactions.append(transaction)
                    else:
                        pass
            else:
                pass


        except:
            pass

        try: 
            self.current_transactions.sort(key=lambda d: d['timestamp'])
        except:
            pass
     

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
        :return: New Block"""

        '''
        This following code sorts the list of current transactions based
        on the time that they occured before the transaciton are verified and the payments occur.
        '''
        
        self.current_transactions.sort(key=lambda d: d['timestamp']) #Sorts
        self.transactionsCheck = self.current_transactions.copy() #Creates copy of self.currentTransactions

        """The follow part of the function verifies payments. Basically, it makes sure that a user is able to pay the amount that the transaction specifies
        It also moves the PyroCoin between users. 

        However, when a user sends money to someone, the program automatically verifies that they can pay, before the transaction is sent. 
        However, only the sender verifies it, so with this system, we have nodes verify this before creating a new block. 
        If this transaction was already verified by the node, they take no action because in their chain, the money has already been transfered. 
        """
        for transaction in self.current_transactions: #Creates a for loop that goes thru all the transactions
            if transaction not in self.verifiedTransactions:
                sender = str(transaction['sender']) #creates a variable equal to the sender's public address
                recipient = str(transaction['recipient']) #creates a variable equal to the recipient's public address
                amount = int(transaction['amount']) #creates a varible equal to the amount
            

                if self.users.get(sender) == None: #Checks if the sender has ever been in a transaction
                    self.users[sender] = 0 #If not, they are added to the list of users, with the net worth being 0

                senderAmount = self.users.get(sender) #Gets the net worth of the sender

                if recipient not in self.users: #Checks if the recipient has ever been in a transaction
                    self.users[recipient] = 0 #If not, they are added to the list of users, with the net worth being 0

                recipientAmount = self.users.get(recipient) #Gets the worth of the recipient

                
                senderAfterTransaction = senderAmount - amount
                print(senderAfterTransaction) 

                if senderAfterTransaction >= 0: #If the transaction amount is greater or equal to the sender's worth, the transaction will occur
                    senderAmount -= amount #subtracts the transaction amount from the worth of the sender
                    self.users[sender] = senderAmount #Actually changes the value of the sender in the userlist

                    recipientAmount += int(amount) #Adds the transaction amount to the worth of the user
                    self.users[recipient] = recipientAmount #Actually changes the value of the recipient in the userlist

                    
                
                elif 0 > senderAfterTransaction: #The sender is unable to afford the transaction
                    self.transactionsCheck.remove(transaction)#Removes the transaction from the transactions list

                self.verifiedTransactions.append(transaction)
                    


            self.current_transactions = self.transactionsCheck.copy()

            block = {
                'index': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': self.current_transactions,
                'proof': proof,
                'previous_hash': previous_hash or self.hash(self.chain[-1]),
            }


            

            # Reset the current list of transactions 
            self.current_transactions = []
            self.transactionsCheck = []
            self.verifiedTransactions = []
            
            
            self.chain.append(block)
            return block


            self.Data = {'Current Transactions': self.current_transactions, 'Verified Transactions': self.verifiedTransactions, 'Chain': self.chain, 'Users': self.users}
            main(self.Data)




    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block
        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount of PryoCoin sent
        :return: The index of the Block that will hold this transaction
        """
        Current_UTC_Time = datetime.utcnow()
        timestamp = int(str(Current_UTC_Time.year) + str(Current_UTC_Time.month) + str(Current_UTC_Time.day) + str(Current_UTC_Time.hour) + str(Current_UTC_Time.minute) + str(Current_UTC_Time.second) + str(Current_UTC_Time.microsecond))
        
        transaction_id = str(str(sender) + str(recipient) + str(amount) + str(timestamp) + str(len(self.chain) + 1)).encode()
        transaction_id = hashlib.sha256(transaction_id).hexdigest()


        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'transaction_id': transaction_id,
            'timestamp': timestamp 
        })

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

