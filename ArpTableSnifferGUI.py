# Not meant for malicious purposes or reconing, I was tasked with making this for a homework assignment for school.
from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether
from scapy.all import *
import os
import PySimpleGUI as sg
from datetime import datetime
def ARPHolder():
    import socket
    HostName = socket.gethostname()
    HostAddress = socket.gethostbyname(HostName)
    #Hostname gethostname retrieve the name of the computer and gethostbyname retrieves the hosts ip address, which will be used later in the Lab
    WhoAmI = {}
    WhoAmI[HostAddress] = HostName
    #Hostaddress and hostname are combined to make a key(hostaddress) and value(hostname)
    HADDSTR = str(HostAddress)
    splitit = HADDSTR.split('.')
    #To get the required NetworkID I had remove the last octet in the IP address, so I converted the Hostaddress into a string and then split it at the '.'
    #The pop function allowed me to remove the 4th octet by index and not string.
    splitit.pop(3)
    y = ''
    for i in splitit:
        y = y+i+'.'
    WhoWeAre = y
    #I then had to recombine the remaining octets together to make the NetworkID
    ARPScanner(WhoWeAre, WhoAmI)
    #In order to pass the NetworkID into the next function I had to declare the function and then add the NetworkID

def ARPScanner(WhoWeAre, WhoAmI):
    i = '0'
    ARPED = {}
    x = 0
    """"""""""""""""""""""""""""""""""""""""""""""
    another way I found to get the arp table, but did not use because of the requirements for the lab.
    # ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='192.168.86.0/24'), timeout=2)
    # for snd, rcv in ans:
    #     ARPED[snd.pdst] = rcv.src
    #     print(ARPED)
    """""""""""""""""""""""""""""""""""""""""""""
    layout = [[sg.Text(WhoWeAre+i,key='_WHO_',enable_events=True)]]
    window = sg.Window("Sniffing",layout)
    for i in range(255):
        i2 = i
        i2 += 1
        i2str = str(i2)
        pp=''
        event, values = window.read(timeout=2)
        if event == sg.WIN_CLOSED:
            window.close()
            break
        import time
        i = str(i)

        window.find_element('_WHO_').Update('Sniffing for'+'\n'+WhoWeAre+i2str)
        print('Sniffing for'+'\n'+WhoWeAre+i)
        ans2, unans2 = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=WhoWeAre+i, hwdst="ff:ff:ff:ff:ff:ff"),timeout=2)
        # Every time this loop is called it combines the I with WhoWeAre to create a full ip address i.e. i = 5 and WhoWeAre = 10.0.0. you get 10.0.0.5
        # Without the timeout at the end of the Ether and Arp, it would search for the same address until the program is shutdown

        for snd,rcv in ans2:
            x+=1
            #if an address had been found the code would announce "Address Found" and see the snd, rcv inside the packets and grab the appropriate addresses
            # and combine them to make a key and value in the ARP Dictionary
            print("Address Found")
            ARPED[snd.pdst] = rcv.src
            time.sleep(.5)

    for k, v in WhoAmI.items():
        print(f"Host Address is {k} and Name is {v}")
        print("IP Address",'   ','Mac Address')
        print(f"Number of Addresses found {x}")
    kv = ''
    vk = ''
    for k,v in ARPED.items():
        print(k,':',v)
        kv += k+'\n'
        vk += v+'\n'
        ### Combines the IP address with their respected Mac address
    x2=str(x)
    window.close()
    DisplayFile(kv,vk,x2,ARPED)


def DisplayFile(IP,MAC,Addnum,ARPED):
    #### Creates a gui that displays the list of IP address and their MAC addresses
    ## The user can also save the address to a file to view for later.
    ttime = datetime.now()
    ttime = str(ttime)
    column1 = [[sg.Text('IP Address'+'\n'+IP)]]
    column2 = [[sg.Text('MAC Addres'+'\n'+MAC)]]
    layout = [[sg.Text('Number of Addresses found: '+Addnum)],[sg.Column(column1),sg.VSeparator(':'),sg.Column(column2),[sg.Button("Save")]]]
    window = sg.Window('ARP Table', layout)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            window.close()
            break
        elif event == 'Save':
            addzip = ''
            addzip += ttime+'\n'
            with open('ARPTABLE.text','a') as g:
                for k, v in ARPED.items():
                    addzip += k+' : '+v+'\n'
                g.write(addzip)
                g.flush()
                g.write('\n')
                g.close()
if __name__ == '__main__':
    ARPHolder()
