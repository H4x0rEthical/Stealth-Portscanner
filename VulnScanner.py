import nmap
import threading

print("1. Scan\n2.ScanVuln(scans for known vulns)\n")
print("If it prints nothing it means there is probably nothing open!\n")
Choice = input("Enter your choice: ")


def Scan(Target):
    Scan = nmap.PortScanner()
    Scan.scan(Target, arguments="-sS")

    for host in Scan.all_hosts():
        print(f"Host: {host} ({Scan[host].hostname()})")
        print(f"State: {Scan[host].state()}")

    for proto in Scan[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = Scan[host][proto].keys()
            for port in ports:
             print(f"Port: {port}, State: {Scan[host][proto][port]['state']}, Service: {Scan[host][proto][port]['name']}")

def ScanVuln(Target):
    Scan = nmap.PortScanner()
    Scan.scan(Target, arguments="-sS --script vuln")

    for host in Scan.all_hosts():
        print(f"Host: {host} ({Scan[host].hostname()})")
        print(f"State: {Scan[host].state()}")

    for proto in Scan[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = Scan[host][proto].keys()
            for port in ports:
             print(f"Port: {port}, State: {Scan[host][proto][port]['state']}, Service: {Scan[host][proto][port]['name']}")


target = "<IP>"
match Choice:
    case "1":
        Scan(target)
    case "2":
        ScanVuln(target)
    
          
