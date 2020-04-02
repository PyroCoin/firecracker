import ast
import socket
import os
from firebase import Firebase




def findStuff():
    config = {
        'apiKey': "AIzaSyD3mdx4IJ4y5l9t16UAXiLsMyQEEDkpSPE",
        'authDomain': "pyrocoinip.firebaseapp.com",
        'databaseURL': "https://pyrocoinip.firebaseio.com",
        'storageBucket': "pyrocoinip.appspot.com",
    }
        
    firebase = Firebase(config)
    
    DataBase = firebase.database()
    


    
    nodeHostName = socket.gethostname()
    IPAddress = socket.gethostbyname(nodeHostName)
    
    


    nodeHostName = socket.gethostname()
    IPAddress = socket.gethostbyname(nodeHostName)
    UserDict = {'IP': IPAddress, 'Port': 5050}
    if os.stat('Endpoints.txt').st_size == 0:
        DataBase.child('users').push(UserDict)

        users = DataBase.child('users').get()
        userDictionaries = users.val().values()
        userIPList = []
        EndpointsData = open('Endpoints.txt', 'w+')

        for data in userDictionaries:
            userIPList.append(data)
            EndpointsData.write("%s\n" % data)
            

            

        print(userIPList)
        EndpointsData.close()
    else:
        EndpointsData = open('Endpoints.txt', 'r+')
        EndpointsData.truncate(0)
        users = DataBase.child('users').get()
        userDictionaries = users.val().values()
        userIPList = []
        with open('Endpoints.txt', 'w') as f:
            for item in userDictionaries:
                userIPList.append(item)
                f.write("%s\n" % item)
        EndpointsData.close()
        print(userIPList)
        
  






        

