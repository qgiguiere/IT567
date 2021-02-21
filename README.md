# IT567
Assignments for BYU IT567 - Pentesting

## Assignment 3
### See file portScanner.py

This program has only been tested to work on Linux with Python 3.8.5

### This code provides the following functionalities:
1. Allow command-line arguments to specify a host and port. 
2. Present a simple response to the user. 
3. Allow more than one host to be scanned
4. Allow multiple ports to be specified
5. Use of TCP or UDP 
6. Create a PDF report

```
python portScanner.py --help
Usage: portScanner.py [OPTIONS]

Options:
  -h, --help  show this help message and exit
  -i I        Target IP address(es). Can be a single address or a range of addresses in format xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx
  -t T        Scans TCP ports. Can be a single port or a range provided in format x-x
  -u U        Scans UDP ports. Can be a single port or a range provided in format x-x
```