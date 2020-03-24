import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request

class BlockChain(object):
    def __init__(self):
        self.chain = []
        self.currentTransactions = []

        self.newBlock(previousHash=1, proof=100)
        #Creates the genesis block

    def newBlock(self):
        '''
        
        '''
        pass

    def newTransaction(self, sender, recipient, amount):
        '''
        Creates a new transaction waiting to be added to the next block. 
        Each new transaction includes the following data:

        Sender: the address of the sender
        Recipient: the adress of the person who is on the recieving end of the transaction
        amount: the amount of money sent 
        '''
        
        self.currentTransactions.append({

            'sender': sender,
            'recipient': recipient
            'amount': amount

            })

            return self.lastBlock['index'] + 1
    
    
    @staticmethod
    def hash(block):
        #Function that hashes a block
        pass

    @property
    def lastBlock(self):
        #returns the last block, creating a blockchain


''' 
This class essentially creates the actual chain
'''