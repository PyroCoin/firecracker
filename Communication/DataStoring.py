import ast
import socket
import os
from firebase import Firebase



class FirebaseConnection:
    def __init__(self):
        self.config = {
        'apiKey': "AIzaSyD3mdx4IJ4y5l9t16UAXiLsMyQEEDkpSPE",
        'authDomain': "pyrocoinip.firebaseapp.com",
        'databaseURL': "https://pyrocoinip.firebaseio.com",
        'storageBucket': "pyrocoinip.appspot.com",
        }
        self.firebase = Firebase(self.config)
        self.dataBase = self.firebase.database()

        self.nodeHostName = socket.gethostname()
        self.IPAddress = socket.gethostbyname(self.nodeHostName)
        self.currentNode = {'IP': self.IPAddress, 'PORT': 5050}
    
    def ReadStorage(self):
        self.ListOfNodeIPs = []
        with open('Endpoints.txt', 'r+') as EndpointsData:
            for line in EndpointsData:
                line = line.strip()
                self.ListOfNodeIPs.append(line)

    def findEndpoints(self):
        if os.stat('Endpoints.txt').st_size == 0:
            self.dataBase.child('users').push(self.currentNode)

            users = self.dataBase.child('users').get()
            userDictionaries = users.val().values()
            self.userIPList = []
            EndpointsData = open('Endpoints.txt', 'w+')

            for data in userDictionaries:
                self.userIPList.append(data)
                EndpointsData.write("%s\n" % data)
            EndpointsData.close()
        else:
            EndpointsData = open('Endpoints.txt', 'r+')
            EndpointsData.truncate(0)
            users = self.dataBase.child('users').get()
            userDictionaries = users.val().values()
            self.userIPList = []
            with open('Endpoints.txt', 'w') as f:
                for item in userDictionaries:
                    self.userIPList.append(item)
                    f.write("%s\n" % item)
            EndpointsData.close()
            

        self.ReadStorage()
        print(self.ListOfNodeIPs)

        








