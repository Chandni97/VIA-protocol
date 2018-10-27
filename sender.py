import socket
from random import *
from hashlib import sha256
from fabulous import text
from fabulous import *
from fabulous.color import bold, magenta, red, green, white
import datetime
import time
import threading



modulus = 23
base = 9
alicePrivateKey = 0
alicePublicKey = 0
bobPublicKey = 0
sharedKey = 0
NextKey = 0
currentKey = 0
firstMessage = True
ip = ('0.0.0.0',5555)
sameMessage=False
sameKeys=False
Message = ""
counter = 0
inception = True
connection = False

#log file path
f = open("Sender-log.txt", "w")

UDP_IP = "127.0.0.1"
UDP_PORT = 5007
MESSAGE = "Hello, World!"


sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))


# send and receive public keys
def exchange_public_keys():
    global bobPublicKey
    global sock
    global connection
    data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
    connection = True
    if (inception):
        print(bold(white("\nConnection Established!!\n\n")))
    sock.settimeout(2)

    bobPublicKey = int(data.decode()[0:])


    global alicePublicKey
    global ip

    alicePublicKey = (base ** alicePrivateKey) % modulus
    sock.sendto(str(alicePublicKey).encode(), addr)
    ip = addr

#calculate first key
def calculate_shared_key():
    global sharedKey
    global inception
    sharedKey = (bobPublicKey**alicePrivateKey) % modulus
    sharedKey = sharedKey % 128

    if(inception):
        f.write("VIA Protocol's Sender Log\n")
        f.write("Communication details: \n")
        f.write("IP address of the reciever : " + ip[0] + "\n")
        f.write("Port number of the receiver : " + str(ip[1]) + "\n")
        f.write("Date and Time : " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + "\n\n")
        f.write("--------------------------------------------------------------------------------------- \n\n")
        f.write("Following are the details of the keys used in the beginning. DONOT SHARE YOUR PRIVATE KEY WITH ANYONE FOR SECURITY PURPOSES")
        f.write("\n\nYour private key : " + str(alicePrivateKey) + "\n")
        f.write("Your public key : " + str(alicePublicKey) + "\n")
        f.write("Receiver's public key : " + str(bobPublicKey) + "\n")
        f.write("The shared key : " + str(sharedKey) + "\n\n")
        f.write("--------------------------------------------------------------------------------------- \n\n")
        inception = False

    else:
        f.write("\n\nYour public key : " + str(alicePublicKey) + "\n")
        f.write("Your private key : " + str(alicePrivateKey) + "\n")
        f.write("Receiver's public key : " + str(bobPublicKey) + "\n")
        f.write("The shared key : " + str(sharedKey) + "\n\n")
        f.write("--------------------------------------------------------------------------------------- \n\n")



def generate_private_key():
    global alicePrivateKey
    alicePrivateKey = randint(1,9999)

def encrypt(string, shift):
    cipher = ''
    for char in string:
        cipher = cipher + chr( (ord(char) + shift) % 128)
    return cipher

def send_message():
    #keep sending messages until user sends :exit
    while(True):
        global Message
        global firstMessage
        global NextKey
        global currentKey
        global ip
        global sameMessage
        global sameKeys
        global counter

        #check if same key has to be used for encryption in case of retransmission
        if(not sameKeys):
            if(firstMessage):
                currentKey = sharedKey
                NextKey = randint(1, 127)
                firstMessage = False
            else:
                currentKey = NextKey
                NextKey = randint(1,127)
        else:
            sameKeys = False

        if(not sameMessage):
            Message = input("Enter the message here : ")
        else:
            sameMessage = False

        # add shared key and next key to the message as a single character
        payload = Message + chr(sharedKey) + chr(NextKey)

        #generate hash
        hash = sha256(payload.encode()).hexdigest()

        #encrypt the message
        cipher = encrypt(payload+hash, currentKey)



        sock.sendto( (str(counter) + str(cipher)).encode(), ip)

        f.write(str(counter) + "." + "\n")
        f.write("Message sent : " + Message + "\n")
        f.write("Next Key : " + str(NextKey) + "\n")
        f.write("Message with payload : " + payload + "\n")
        f.write("Hash of the message with payload : " + hash + "\n")
        f.write("Encrption : " + cipher + "\n")


        #check if ack recieved or not
        try:
            data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
        except Exception:
            print(bold(red("Connection timed out. ACK not received. Sending the message again\n")))
            f.write("Connection timed out. ACK not received. Sending the message again" + "\n")
            sameMessage = True
            sameKeys = True
            continue

        #check if ack/nack received
        valid = int(data.decode()[0:])
        if(valid == 0):
            print(bold(red("NACK recieved. Generating and exchanging keys again. Sending the message again \n")))
            f.write("NACK recieved. Generating and exchanging keys again. Sending the message again \n")
            counter = 0
            firstMessage = True
            sameMessage = True
            diffie_hellman()
            break
        else:
            f.write("ACK recieved\n")
            counter = counter + 1


        f.write("\n")

        #end connection if :exit sent
        if(Message == ":exit"):
            end_connection()
            break

#generate first key using diffie hellman key exchange
def diffie_hellman():
    generate_private_key()
    exchange_public_keys()
    calculate_shared_key()
    send_message()

def end_connection():
    sock.close()
    print(bold(white("\n\nConnection closed!!!")))
    print(text.Text("                 END", color='#288D28', shadow=False, skew=1, fsize=10))
    f.write("\n\n ------------------------------------------------------------------------------\n")
    f.write("\n\nConnection Closed\n")
    f.write("Total Messages : " + str(counter)+"\n")
    f.write("Date and Iime : " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + "\n\n")
    f.close()


def waiting_for_connection():
    print("\n\n")
    print(text.Text("              VIA Protocol", color='#288D28', shadow=False, skew=1, fsize=10))
    print(bold(white("SENDER'S PLATFORM \n")))
    print(bold(white("Check logs in Sender-log.txt when the communication has ended\n")))
    print(bold(white("Type ':exit' to end the communication\n")))
    print(bold(white("Waiting to connect")))
    global connection
    animation = "|/-\\"
    idx = 0
    while not connection:
        print(animation[idx % len(animation)], end="\r")
        idx += 1
        time.sleep(0.1)



threading.Thread(target=diffie_hellman).start()
threading.Thread(target=waiting_for_connection).start()



