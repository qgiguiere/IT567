import sys
import argparse
import socket
import subprocess
import time
import fpdf
import netaddr
from argparse import ArgumentParser
import ipaddress

parser = ArgumentParser()
parser.add_argument("-i", help="Target IP address(es). Can be a single address or a range of addresses in format xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx")
parser.add_argument("-t", help="Scans TCP ports. Can be a single port or a range provided in format x-x")
parser.add_argument("-u", help="Scans UDP ports. Can be a single port or a range provided in format x-x")

args = parser.parse_args()

pdf = fpdf.FPDF(format='letter') #Create the PDF
pdf.add_page()
pdf.set_font("Arial", size=14)

if args.i:
    startTime = time.perf_counter() #start the timer
    if '-' in args.i: #for an IP range
        rangeIP = args.i.split('-')
        startIP = rangeIP[0]
        endIP = rangeIP[1]
        IPs = netaddr.IPRange(startIP, endIP)
        for ip in IPs:
            ipAddress = int(ipaddress.ip_address(ip))
            ipStr = ipaddress.ip_address(ipAddress).__str__()
            scanIP = socket.gethostbyname(str(ipAddress))
            print('Scanning ' + ipStr + '\n')
            if args.t:
                if '-' in args.t: #for an TCP range
                    rangePort = args.t.split('-')
                    startPort = rangePort[0]
                    endPort = rangePort[1]
                    Ports = range(int(startPort), int(endPort)+1)
                    pdf.write(5,"Host: " + str(ipStr))
                    pdf.write(5,"\nPort Range: " + args.t + "\n")
                    pdf.write(5,"\nOpen TCP Ports:\n\n")
                    for port in Ports:
                        print ("Now scanning port ",port, '\n')
                        try:
                            scannerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            result = scannerSocket.connect_ex((scanIP, port))
                            if result == 0:
                                print ("TCP Port " + str(port) + " is Open\n")
                                pdf.write(5,"Port " + str(port) + " is Open\n")
                            scannerSocket.close()
                        except KeyboardInterrupt:
                            print ("\nPort scan canceled")
                            sys.exit()
                        except socket.gaierror:
                            print ("\nCannot resolve hostname. Exiting program")
                            sys.exit()
                        except socket.error:
                            print ("\nCannot connect to the server")
                            sys.exit()
                    pdf.write(5,"\n\n\n---------------------------------------------\n\n")
                else:
                    intT = int(args.t)
                    print ("Now scanning port ",intT, '\n')
                    pdf.write(5,"Host: " + ipStr)
                    pdf.write(5,"Port Range: " + str(intT) + "\n")
                    pdf.write(5,"\nOpen TCP Ports:")
                    try:
                        scannerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        result = scannerSocket.connect_ex((scanIP, intT))
                        if result == 0:
                            print ("TCP Port " + str(intT) + " is Open\n")
                            pdf.write(5,"Port " + str(intT) + " is Open")
                        scannerSocket.close()
                    except KeyboardInterrupt:
                        print ("\nPort scan canceled")
                        sys.exit()
                    except socket.gaierror:
                        print ("\nCannot resolve hostname. Exiting program")
                        sys.exit()
                    except socket.error:
                        print ("\nCannot connect to the server")
                        sys.exit()
                    pdf.write(5,"\n\n\n---------------------------------------------\n\n")
            if args.u:
                if '-' in args.u: #for a UDP range
                    rangePort = args.u.split('-')
                    startPort = rangePort[0]
                    endPort = rangePort[1]
                    Ports = range(int(startPort), int(endPort)+1)
                    pdf.write(5,"Host: " + str(ipStr))
                    pdf.write(5,"\nPort Range: " + args.u + "\n")
                    pdf.write(5,"\nOpen UDP Ports:\n\n")
                    for port in Ports:
                        print ("Now scanning port ",port, '\n')
                        try:
                            udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            udpResult = udpSocket.connect_ex((scanIP, port))
                            if udpResult == 0:
                                print ("UDP Port " + str(port) + " is Open\n")
                                pdf.write(5,"Port " + str(port) + " is Open\n")
                            udpSocket.close()
                        except KeyboardInterrupt:
                            print ("\nPort scan canceled")
                            sys.exit()
                        except socket.gaierror:
                            print ("\nCannot resolve hostname. Exiting program")
                            sys.exit()
                        except socket.error:
                            print ("\nCannot connect to the server")
                            sys.exit()
                    pdf.write(5,"\n\n\n---------------------------------------------\n\n")
                else:
                    intU = int(args.u)
                    print ("Now scanning port ",intU, '\n')
                    pdf.write(5,"Host: " + str(ipStr))
                    pdf.write(5,"\nPort Range: " + str(intU) + "\n")
                    pdf.write(5,"\nOpen UDP Ports:\n\n")
                    try:
                        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        udpResult = udpSocket.connect_ex((scanIP, intU))
                        if udpResult == 0:
                            print ("UDP Port " + str(intU) + " is Open\n")
                            pdf.write(5,"Port " + str(intU) + " is Open")
                        udpSocket.close()
                    except KeyboardInterrupt:
                        print ("\nPort scan canceled")
                        sys.exit()
                    except socket.gaierror:
                        print ("\nCannot resolve hostname. Exiting program")
                        sys.exit()
                    except socket.error:
                        print ("\nCannot connect to the server")
                        sys.exit()
                    pdf.write(5,"\n\n\n---------------------------------------------\n\n")
    else:
        ipAddress = int(ipaddress.ip_address(args.i))
        ipStr = ipaddress.ip_address(ipAddress).__str__()
        scanIP = socket.gethostbyname(str(ipAddress))
        print('Scanning ' + ipStr + '\n')
        if args.t:
            if '-' in args.t: #for a TCP range
                rangePort = args.t.split('-')
                startPort = rangePort[0]
                endPort = rangePort[1]
                Ports = range(int(startPort), int(endPort)+1)
                pdf.write(5,"Host: " + str(ipStr))
                pdf.write(5,"\nPort Range: " + args.t + "\n")
                pdf.write(5,"\nOpen TCP Ports:\n\n")
                for port in Ports:
                    print ("Now scanning port ",port, '\n')
                    try:
                        scannerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        result = scannerSocket.connect_ex((scanIP, port))
                        if result == 0:
                            print ("TCP Port " + str(port) + " is Open\n")
                            pdf.write(5,"Port " + str(port) + " is Open\n")
                        scannerSocket.close()
                    except KeyboardInterrupt:
                        print ("\nPort scan canceled")
                        sys.exit()
                    except socket.gaierror:
                        print ("\nCannot resolve hostname. Exiting program")
                        sys.exit()
                    except socket.error:
                        print ("\nCannot connect to the server")
                        sys.exit()
                pdf.write(5,"\n\n\n---------------------------------------------\n\n")
            else:
                intT = int(args.t)
                print ("Now scanning port ",intT, '\n')
                pdf.write(5,"Host: " + str(ipStr))
                pdf.write(5,"Port Range: " + str(intT) + "\n")
                pdf.write(5,"\nOpen TCP Ports:")
                try:
                    scannerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = scannerSocket.connect_ex((scanIP, intT))
                    if result == 0:
                        print ("TCP Port " + str(intT) + " is Open\n")
                        pdf.write(5,"Port " + str(intT) + " is Open")
                    scannerSocket.close()
                except KeyboardInterrupt:
                    print ("\nPort scan canceled")
                    sys.exit()
                except socket.gaierror:
                    print ("\nCannot resolve hostname. Exiting program")
                    sys.exit()
                except socket.error:
                    print ("\nCannot connect to the server")
                    sys.exit()
                pdf.write(5,"\n\n\n---------------------------------------------\n\n")
        if args.u:
            if '-' in args.u: #for a UDP range
                rangePort = args.u.split('-')
                startPort = rangePort[0]
                endPort = rangePort[1]
                Ports = range(int(startPort), int(endPort)+1)
                pdf.write(5,"Host: " + str(ipStr))
                pdf.write(5,"\nPort Range: " + args.u + "\n")
                pdf.write(5,"\nOpen UDP Ports:\n\n")
                for port in Ports:
                    print ("Now scanning port ",port, '\n')
                    try: 
                        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        udpResult = udpSocket.connect_ex((scanIP, port))
                        if udpResult == 0:
                            print ("UDP Port " + str(port) + " is Open\n")
                            pdf.write(5,"Port " + str(port) + " is Open\n")
                        udpSocket.close()
                    except KeyboardInterrupt:
                        print ("\nPort scan canceled")
                        sys.exit()
                    except socket.gaierror:
                        print ("\nCannot resolve hostname. Exiting program")
                        sys.exit()
                    except socket.error:
                        print ("\nCannot connect to the server")
                        sys.exit()
                pdf.write(5,"\n\n\n---------------------------------------------\n\n")
            else:
                intU = int(args.u)
                print ("Now scanning port ",intU, '\n')
                pdf.write(5,"Host: " + str(ipStr))
                pdf.write(5,"\nPort Range: " + str(intU) + "\n")
                pdf.write(5,"\nOpen UDP Ports:\n\n")
                try:
                    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udpResult = udpSocket.connect_ex((scanIP, intU))
                    if udpResult == 0:
                        print ("UDP Port " + str(intU) + " is Open\n")
                        pdf.write(5,"Port " + str(intU) + " is Open")
                    udpSocket.close()
                except KeyboardInterrupt:
                    print ("\nPort scan canceled")
                    sys.exit()
                except socket.gaierror:
                    print ("\nCannot resolve hostname. Exiting program")
                    sys.exit()
                except socket.error:
                    print ("\nCannot connect to the server")
                    sys.exit()
                pdf.write(5,"\n\n\n---------------------------------------------\n\n")
    scanTime = time.perf_counter() - startTime #end the timer
    print ("\nScanning complete. Scan Time:", scanTime, " seconds")
    pdf.write(5,"Scan Time: " + str(scanTime) + " seconds")
pdf.output("scanResults.pdf")