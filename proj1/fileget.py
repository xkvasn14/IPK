import sys
import socket
import re
import os


#--- INITIALIZATION ---
NAMESERVER = ""
SURL = ""
#--- END INITIALIZATION ---

#--- FUNCTIONS ---
def download(HOST, PORT, MESSAGE, HOSTNAME, AGENT, FILENAME):
    # Server file connection / download / write / error handling
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect((HOST, PORT))
    s.send(MESSAGE.encode())
    s.send(HOSTNAME.encode())
    s.send(AGENT.encode())
    try:
        with open(os.path.join(os.getcwd(), FILENAME), 'wb') as file_to_write:
            while True:
                data = s.recv(1024)
                if not data:
                    break
                arr = data.split(b'\r\n\r\n')
                if (len(arr) == 2):
                    ErrorHandler(FILENAME, arr[0])
                    arr2 = arr[1]
                else:
                    arr2 = arr[0]
                file_to_write.write(arr2)
            file_to_write.close()
        s.close()
    except OSError:
        sys.exit("System Error")

def ErrorHandler(FILE, MESSAGE):
    # Handling TCP connection errors
    arr = MESSAGE.split(b'\r\n')
    if(arr[0] == b'FSP/1.0 Not Found'):
        os.remove(FILE)
        sys.exit("Not Found")
    elif(arr[0] == b'FSP/1.0 Bad Request'):
        os.remove(FILE)
        sys.exit("Bad Request")
    elif(arr[0] == b'FSP/1.0 Server Error'):
        os.remove(FILE)
        sys.exit("Server Error")
    elif(arr[0] == b'FSP/1.0 Success'):
        return
    else:
        return
#--- END FUNCTIONS ---

#--- PARAMS CHECK ---
if len(sys.argv) != 5:
    sys.exit("Wrong number of arguments")

# IP address check / server name check
if(sys.argv[1] == "-n" and sys.argv[3] == "-f"):
    if(re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\:\d{1,5}$",sys.argv[2])):
        NAMESERVER = sys.argv[2]
    else:
        sys.exit("IP address not valid")
    if(re.match(r"^fsp://",sys.argv[4])):
       SURL = sys.argv[4]
    else:
        sys.exit("Wrong FSP Protocol")
    SURL = re.sub(r"^fsp://","",SURL)
    SURL = re.sub(r"[*]","",SURL)
    if(re.sub(r"[a-zA-Z0-9\/\-\_\.]","",SURL) != ""):
        print(re.sub(r"[a-zA-Z0-9/\-\_\.[*]", "", SURL))
        sys.exit("Wrong SURL")
    SURL = sys.argv[4]
# server name check / IP address check
elif (sys.argv[1] == "-f" and sys.argv[3] == "-n"):
    if (re.match(r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\:\d{1,5}$", sys.argv[4])):
        NAMESERVER = sys.argv[4]
    else:
        sys.exit("IP address not valid")
    if(re.match(r"^fsp://",sys.argv[2])):
        SURL = sys.argv[2]
    else:
        sys.exit("Wrong FSP Protocol")
    SURL = re.sub(r"^fsp://", "", SURL)
    SURL = re.sub(r"[*]", "", SURL)
    if (re.sub(r"[a-zA-Z0-9/\-\_\.]", "", SURL) != ""):
        sys.exit("Wrong SURL")
    SURL = sys.argv[2]
else:
    sys.exit("Wrong arguments")
#--- END PARAMS CHECK ---

# UDP connection
HOST,PORT = re.split(r":",NAMESERVER)
PORT = int(PORT)

SURL = re.sub(r"^fsp://","",SURL)
array = re.split(r"/",SURL)

SERVER = array[0]
PATHANDFILE = "/".join(array[1:])
FILENAME = array[-1]
MESSAGE = "WHEREIS " + SERVER

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    s.connect((HOST, PORT))
    s.send(MESSAGE.encode())
    data = s.recv(1024)
    RECV_MESSAGE = data.decode()
except:
    sys.exit("Timed Out")

if(re.match(r"^ERR Syntax",RECV_MESSAGE)):
    sys.exit("ERR Syntax")
elif(re.match(r"^ERR Not Found",RECV_MESSAGE)):
    sys.exit("ERR Not Found")
# END UDP connection

if(FILENAME != '*'):
    #GET or index
    HOST2, PORT2 = re.split(r":", re.sub(r"^OK ", "", data.decode()))
    PORT2 = int(PORT2)
    MESSAGE = "GET " + PATHANDFILE + " FSP/1.0\r\n"
    HOSTNAME = "Hostname: " + SERVER + "\r\n"
    AGENT = "Agent: " + "xkvasn14" + "\r\n\r\n"
    download(HOST2, PORT2, MESSAGE, HOSTNAME, AGENT, FILENAME)
else:
    #GETALL
    HOST2, PORT2 = re.split(r":", re.sub(r"^OK ", "", data.decode()))
    PORT2 = int(PORT2)
    MESSAGE = "GET " + PATHANDFILE + " FSP/1.0\r\n"
    HOSTNAME = "Hostname: " + SERVER + "\r\n"
    AGENT = "Agent: " + "xkvasn14" + "\r\n\r\n"

    FILE_PATHS=[]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect((HOST2, PORT2))
    s.send(b'GET index FSP/1.0\r\n')
    s.send(HOSTNAME.encode())
    s.send(AGENT.encode())
    while True:
        data = s.recv(1024)
        if not data:
            break
        FILE_PATHS_arr = (re.split(r"\r\n\r\n", data.decode()))
    s.close()
    if(len(FILE_PATHS_arr) == 2):
        FILE_PATHS_arr = FILE_PATHS_arr[1]
    else:
        FILE_PATHS_arr = FILE_PATHS_arr[0]
    FILE_PATHS = re.split(r"\r\n",FILE_PATHS_arr)
    FILE_PATHS.pop(-1)
    for PATH in FILE_PATHS:
        MESSAGE = "GET " + PATH + " FSP/1.0\r\n"
        FILENAMES = re.split(r"/",PATH)
        FILENAME = FILENAMES[-1]
        download(HOST2, PORT2, MESSAGE, HOSTNAME, AGENT, FILENAME)