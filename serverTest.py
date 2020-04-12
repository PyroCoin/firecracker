from Communication.appServer import Server
import threading



Server = Server('', 5050)


listeningthread = threading.Thread(target=Server.mainConnection)
incomingDataThread = threading.Thread(target=Server.incomingData)

listeningthread.start()
incomingDataThread.start()

