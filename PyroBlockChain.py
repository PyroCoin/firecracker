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

    def newBlock(self):
        #Makes a new block
        pass
    def newTransaction(self):
        #Creates a transaction
        pass
    
    
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