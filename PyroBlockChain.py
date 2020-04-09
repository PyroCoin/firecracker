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
import tkinter as tk
from tkinter.ttk import *
import time
from functools import partial
from uuid import uuid4
from hashlib import sha256
import binascii
import os

from GenerateSignedTransaction import CreateSignature

from Communication.DataStoring import FirebaseConnection
from Communication.appClient import Clientmain
from Communication.appServer import Server 
import requests



UI_Style = Style()

def verify_signature(signature, text, public_key):
    url = 'https://crows.sh/verifySignature'
    body = {'signature': signature, "transactionRepresentation": text, "publicKey": public_key}

    x = requests.post(url, data=body)

    return x.json()["valid_signature"]


class Blockchain:
    def __init__(self):
        Current_UTC_Time = datetime.utcnow()
        timestamp = int(str(Current_UTC_Time.year) + str(Current_UTC_Time.month) + str(Current_UTC_Time.day) + str(Current_UTC_Time.hour) + str(Current_UTC_Time.minute) + str(Current_UTC_Time.second) + str(Current_UTC_Time.microsecond))
        
        self.genesisBlock = {
                'index': 1,
                'timestamp': timestamp,
                'transactions': [],
                'proof': 100,
                'previous_hash': 1,
            }
        self.current_transactions = []
        self.chain = [self.genesisBlock]
        self.nodes = set()
        self.users = {'0': 250000000}
        self.transactionsCheck = []
        self.verifiedTransactions = []
        self.Transactions = {}
        self.Mine_Prize = 64 
        
        


        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def CheckNewData(self, data_list):
        for data in data_list:
            try:
                
                Chain = data.get('Chain')
                Transactions = data.get('Current Transactions')
                Users = Users.get('Users')



                if len(Chain) > len(self.chain) and len(Users) > len(self.users):
                    self.chain = Chain
                    self.current_transactions = Transactions
                    self.users = Users
                    self.current_transactions.sort(key=lambda d: d['timestamp'])
                    if len(Transactions) != 0:
                        for Transaction in Transaction:
                            if Transaction not in self.current_transactions:
                                self.current_transactions.append(Transaction)
                        self.current_transactions.sort(key=lambda d: d['timestamp'])

                else:
                    if len(Transactions) != 0:
                        for Transaction in Transaction:
                            if Transaction not in self.current_transactions:
                                self.current_transactions.append(Transaction)
                        self.current_transactions.sort(key=lambda d: d['timestamp'])

                        for user in Users():
                            if user not in self.users:
                                self.users.append(user)



            except:
                pass



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


            Current_UTC_Time = datetime.utcnow()
            timestamp = int(str(Current_UTC_Time.year) + str(Current_UTC_Time.month) + str(Current_UTC_Time.day) + str(Current_UTC_Time.hour) + str(Current_UTC_Time.minute) + str(Current_UTC_Time.second) + str(Current_UTC_Time.microsecond))
        
            block = {
                'index': len(self.chain) + 1,
                'timestamp': timestamp,
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
            Clientmain(self.Data)




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

        self.Data = {'Current Transactions': self.current_transactions, 'Verified Transactions': self.verifiedTransactions, 'Chain': self.chain, 'Users': self.users}
        Clientmain(self.Data)

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
        return guess_hash[:7] == "0000000"

    
    def polishChainDisplay(chain):
        pass





# Instantiate the Node
app = Flask(__name__)

# ---------------------[Routes]--------------------- #

node_public_key = 1

# Instantiate the Blockchain
blockchain = Blockchain()
FirebaseStorage = FirebaseConnection()
RecieverServer = Server('', 5050) 



def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_public_key,
        amount=blockchain.Mine_Prize,
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
    



def new_transaction(TransactionData, root):
    #DictionaryData = {'sender': sender, 'recipient': recipient, 'amount': amount, 'PrivateKey': privKey}

    signature = CreateSignature(TransactionData.get('PrivateKey'), TransactionData.get('sender'), TransactionData.get('recipient'), TransactionData.get('amount'))
    print(signature)

    if signature == 'Incorrect Data':
        try:
            Error.destroy()
            Error = tk.Label(root, text='Incorrect Data')
            Error.pack()
        except:
            Error = tk.Label(root, text='Incorrect Data')
            Error.pack()





    else:
        TransactionDataDict = {'sender': TransactionData.get('sender'), 'recipient': TransactionData.get('recipient'), 'amount': TransactionData.get('amount'), 'signature': signature}
        values = TransactionDataDict
        # Check that the required fields are in the POST'ed data
        required = ['signature', 'sender', 'recipient', 'amount']
        if not all(k in values for k in required):
            MissingValues = tk.Label(root, text='Missing values')
            MissingValues.pack()

        unsigned_transaction_format = f"{values['sender']} -{values['amount']}-> {values['recipient']}"

        # Verify signature is valid
        if not verify_signature(values['signature'], unsigned_transaction_format, values['sender']):
            badSignature = tk.Label(root, text='Your signature does not verify your transaction')
            badSignature.pack()

        try:
            # Create a new Transaction
            blockchain.new_transaction(TransactionData.get('sender'), TransactionData.get('recipient'), TransactionData.get('amount'), root)

        except:
            pass


def full_chain():
    return(blockchain.chain)

    
def users():
    return str(blockchain.users)

class PyroInterface(tk.Frame):
    def __init__(self, userKey, privateKey, root):
        self.userKey = userKey
        self.privateKey = privateKey
        tk.Frame.__init__(self, root)
        root.winfo_toplevel().title('PyroCoin Full Node')

        Welcome = tk.Message(root, text='Welcome to the Pyrocoin Full Node Service. As a full node, you will help manage the Blockchain by verifying payments and handling requests. The reward for this hard work will be newly generated PyroCoin!')
        Welcome.pack()

        LoginBTN = tk.Button(root, text='Enter A Private Key to Login', command=self.Login)
        LoginBTN.pack()

        NewKeys = tk.Button(root, text='Generate a new Public and Private Key', command=self.Signup)
        NewKeys.pack()


    def remove(self):
        for widget in root.winfo_children():
            widget.destroy()
        
    def GoBack(self):
        backBTN = tk.Button(root, text='Back', command=self.main)
        backBTN.pack()

    def Welcome(self):
        for widget in root.winfo_children():
            widget.destroy()
        Welcome = tk.Message(root, text='Welcome to the Pyrocoin Full Node Service. As a full node, you will help manage the Blockchain by verifying payments and handling requests. The reward for this hard work will be newly generated PyroCoin!')
        Welcome.pack()

        LoginBTN = tk.Button(root, text='Enter A Private Key to Login', command=self.Login)
        LoginBTN.pack()

        NewKeys = tk.Button(root, text='Generate a new Public and Private Key', command=self.Signup)
        NewKeys.pack()  


    def Login(self):
        for widget in root.winfo_children():
            widget.destroy()
        
        PrivateKeyMessage = tk.Message(root, text='Enter your Private Key')
        PrivateKeyMessage.pack()
        self.PrivateKeyText = tk.Text(root, height=1, width=70)
        self.PrivateKeyText.pack()



        SubmitBTN = tk.Button(root, text='Submit', command=self.CheckData)
        SubmitBTN.pack()


    def Signup(self):
        for widget in root.winfo_children():
            widget.destroy()
        KeepSafe = tk.Label(root, text='These are your new keys. Please keep these safe. If someone were to steal this, they would be able to take away all your PyroCoin!')

        YourNewPublicKey = tk.Text(root, height=1, width=100, borderwidth=0)
        YourNewPublicKey.insert(1.0, str('Your new public key is ' + str(self.userKey)))
        YourNewPublicKey.pack()

        YourNewPrivateKey = tk.Text(root, height=1, width=100, borderwidth=0)
        YourNewPrivateKey.insert(1.0, str('Your new private key is ' + str(self.privateKey)))
        YourNewPrivateKey.pack()
        
        
        KeepSafe.pack()
        
        backBTN = tk.Button(root, text='Continue', command=self.main)
        backBTN.pack()

    def CheckData(self):
        priv = self.PrivateKeyText.get('1.0', 'end-1c')
        
        
        else:
            privList = list(priv)
            for string in privList:
                if string == ' ':
                    del(privList[privList.index(string)])
            pub = sha256(priv.encode()).hexdigest()

            
            for widget in root.winfo_children():
                widget.destroy()
            
            
            Approved = tk.Label(root, text=str('Is your public key \n' + pub))
            Approved.pack()
            ContBTN = tk.Button(root, text='Continue', command=self.main)
            ContBTN.pack()
            backBTN = tk.Button(root, text='Back', command=self.Welcome)
            backBTN.pack()
            self.userKey = pub

    





    def mineBlocks(self):
        for widget in root.winfo_children():
            widget.destroy()

        Mining = tk.Label(root, text='Please wait while PyroCoin is mined, this may take a while!')
        Mining.pack()
        mine()
        Mining.pack_forget()
        label2 = tk.Label(root, text=str('The Block has been mined, you have gained ' + str(blockchain.Mine_Prize) + ' Pyrocoin!'))
        label2.pack()
        self.GoBack()

    def mine(self):
        for widget in root.winfo_children():
            widget.destroy()

        StartMine = tk.Button(root, text='Mine Block', command=self.mineBlocks)
        MineWarning = tk.Message(root, text='Warning! Mining may take some time!')
        StartMine.pack()
        MineWarning.pack()
        self.GoBack()



    def users(self):       
        for widget in root.winfo_children():
            widget.destroy()
        users = tk.Label(root, text=blockchain.users)
        users.pack()
        self.GoBack()
        

    def full_chain(self):
        for widget in root.winfo_children():
            widget.destroy()
        entireChain = tk.Message(root, text=blockchain.chain)
        entireChain.pack()

        self.GoBack()

    
    
    def new_transactions(self):
        for widget in root.winfo_children():
            widget.destroy()


        Recipient_Them = tk.Label(root, text='Recipient')  
        Recipient_Them.pack()
        self.Recipient = tk.Text(root, height=1, width=50)
        self.Recipient.pack()

        AmountData = tk.Label(root, text='Amount')  
        AmountData.pack()
        self.Amount = tk.Text(root, height=1, width=50)
        self.Amount.pack()

        privateKeyLab = tk.Label(root, text='Your Private Key')  
        privateKeyLab.pack()
        self.privateKey = tk.Text(root, height=1, width=50)
        self.privateKey.pack()



        btn_submit = tk.Button(root, text="Submit", command=self.getAndUseData)
        btn_submit.pack()

    def getAndUseData(self):
        privKey =  self.privateKey.get("1.0",'end-1c')
        amount = self.Amount.get('1.0', 'end-1c')
        recipient = self.Recipient.get('1.0', 'end-1c')
        sender = self.userKey

        print(privKey)
        print(amount)
        print(recipient)
        print(sender)
        
        DictData = {'sender': sender, 'recipient': recipient, 'amount': amount, 'PrivateKey': privKey}
        
        new_transaction(DictData, root)

        
            

        
    
    def main(self):
        for widget in root.winfo_children():
            widget.destroy()

        btn_users = tk.Button(root, text='Users', command=self.users)
        btn_fullChain = tk.Button(root, text='Chain', command=self.full_chain)
        btn_newTransaction = tk.Button(root, text='New Transaction', command=self.new_transactions)
        btn_mine = tk.Button(root, text="Mine A Block", command = self.mine)

        btn_fullChain.pack()
        btn_users.pack()
        btn_newTransaction.pack()
        btn_mine.pack()


        
    
        


if __name__ == '__main__':
    from argparse import ArgumentParser

    root = tk.Tk()
    parser = ArgumentParser()

    



    
    privateKey = os.urandom(32)
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    node_public_key = '04' + binascii.hexlify(vk.to_string()).decode()
    



    if node_public_key == "0":
        raise ValueError("You must specify a node key!")
    


    UI = PyroInterface(node_public_key, privateKey, root)


    UI.pack(side="top", fill="both", expand=True)
    root.mainloop()
    

  


