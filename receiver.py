import socket
from random import *
from hashlib import sha256
from fabulous import text
from fabulous import *
from fabulous.color import bold, magenta, red, green, white, fg256
import datetime
import time


modulus = 23
base = 9
bobPrivateKey = 0
bobPublicKey = 0
sharedKey = 0
alicePublicKey = 0
firstMessage = True
NextKey = 0
#log file path
f = open("Receiver-logs.txt", "w")
counter = 0
response = False

UDP_IP = "127.0.0.1"
UDP_PORT = 5007

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP


#cacluclates the first key
def calculate_shared_key():
    global sharedKey
    sharedKey = (alicePublicKey**bobPrivateKey) % modulus
    sharedKey = sharedKey % 128
    f.write("The shared key : " + str(sharedKey)+"\n\n")

    f.write("--------------------------------------------------------------------------------------- \n\n")


def generate_private_key():
    global bobPrivateKey
    bobPrivateKey = randint(1, 9999)
    f.write("\n\nYour private key : "+ str(bobPrivateKey)+"\n")

def exchange_public_keys():
    global bobPublicKey
    bobPublicKey = (base ** bobPrivateKey) % modulus
    f.write("Your public key : " + str(bobPublicKey)+"\n")
    sock.sendto(str(bobPublicKey).encode(), (UDP_IP, UDP_PORT))

    global alicePublicKey
    data = sock.recvfrom(1024)  # buffer size is 1024 bytes
    alicePublicKey = int(data[0].decode()[0:])
    f.write("Sender's public key : "+ str(alicePublicKey)+"\n")

#uses the key as shift to decrypt
def decrypt(string, shift):
    cipher = ''
    for char in string:
        cipher = cipher + chr( (ord(char) - shift) % 128)
    return cipher

#perform diffie hellman key exchange
def diffie_hellman():
    generate_private_key()
    exchange_public_keys()
    calculate_shared_key()
    receive_message()

def receive_message():
    global counter
    while(True): #keep receiving messages until :exit received
        global firstMessage
        global NextKey
        global currentKey
        global response
        data = sock.recvfrom(2048)  #buffer size is 2048
        counterMessage = data[0].decode()[0] #the message sequence received from the sender

        sent = data[0].decode()[1:] # encrypted message,vshared key, next key and hash
        f.write(str(counter) + "."+"\n")
        f.write("Encrypted data recieved : "+sent+"\n")

        if(firstMessage): #use shared key if it is a first message
            plain = decrypt(sent, sharedKey)
            currentKey = sharedKey
            firstMessage = False
        else:
            if(int(counterMessage) != counter ): #use previous key if the message has been sent again
                plain = decrypt(sent, currentKey) # decryption
                counter = counter - 1
            else:
                currentKey = NextKey
                plain = decrypt(sent, NextKey) # decryption

        f.write("Decrypted data : " + plain+"\n")

        hashReceived = plain[-64:] #
        f.write("Hash of the data : " + hashReceived+"\n") # hash recieved

        NextKeyString = plain[-65]
        NextKey = ord(NextKeyString)
        f.write("Next Key to be used : " + str(NextKey)+"\n") # next key to be used

        key = plain[-66]
        f.write("Shared Key received : " + str(ord(key))+"\n") # the shared key

        message = plain[:-66] # the message
        f.write("Plain message : " + message+"\n")
        print(bold(fg256('#288D28', str(counter) + ". ")), end='')
        print(message)

        #calculate the hash
        Message = message + key + NextKeyString
        hash = sha256(Message.encode()).hexdigest()
        f.write("Calculated hash of the data : " + hash+"\n")

        #compare hash and shared key for integrity and veritification
        if(hash == hashReceived and ord(key) == sharedKey):     #add and counter!=6 over here for test invalid mesages
            f.write("Message is valid"+"\n")
            sock.sendto(str(1).encode(), (UDP_IP, UDP_PORT))

            '''if(counter != 2):                                        #use this to test for timed out response
                sock.sendto(str(1).encode(), (UDP_IP, UDP_PORT))
            if(counter == 2 and response):
                sock.sendto(str(1).encode(), (UDP_IP, UDP_PORT))
            else:
                time.sleep(10)
                response = True'''

        else:
            print(bold(red("Message is invalid. Generating and exchanging public keys again"+"\n")))
            f.write("Message is invalid. Generating and exchanging public keys again"+"\n")
            sock.sendto(str(0).encode(), (UDP_IP, UDP_PORT))
            firstMessage = True
            counter = 0
            diffie_hellman() #exchange keys again
            break
        counter = counter + 1
        f.write("\n")

        if (message == ":exit"):
            end_connection()
            break

def end_connection():
    sock.close()
    f.write("\n\n ------------------------------------------------------------------------------\n")
    f.write("\n\nConnection Closed\n")
    f.write("Total Messages : " + str(counter) + "\n")
    f.write("Date and Iime : " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + "\n\n")
    f.close()
    print(bold(white("\n\nConnection closed!!!")))
    print(text.Text("                  END", color='#288D28', shadow=False, skew=1, fsize=10))


f.write("VIA Protocol's Reciever Log\n")
f.write("Communication details: \n")
f.write("IP address of the sender : " + UDP_IP + "\n")
f.write("Port number of the sender : " + str(UDP_PORT) + "\n")
f.write("Date and Time : " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + "\n\n")
f.write("--------------------------------------------------------------------------------------- \n\n")
f.write("Following are the details of the keys used in the beginning. DONOT SHARE YOUR PRIVATE KEY WITH ANYONE FOR SECURITY PURPOSES")

print("\n\n")
print(text.Text("              VIA Protocol", color='#288D28', shadow=False, skew=1, fsize=10))
print(bold(white("SENDER'S PLATFORM \n")))
print(bold(white("Check logs in Receiver-logs.txt when the communication has ended\n")))
print(bold(white("Connection Established\n")))

diffie_hellman()





