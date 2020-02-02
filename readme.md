Author: Pupul Mayank


This script takes input in the format of snc [-l] [--key KEY] [destination] [port]. Here -l identifies the server side. This script is meant for creating a bi-directional encrypted server-client transaction. This script has been tested against python 3.7.4.

The modules necessarily used in this script are sys, socket, time, logging, argparse, select, pycryptodome, base64, json and os. The requirements file is attached which can be used to install pycryptodome. Other modules are by default present in python 3.7.4, but in case they are missing, it will be required that they be installed for running the script.


Below mentioned examples should be used as format to execute the scripts:
                                
# start client
./snc --key CSC574ISAWESOME server-address 9999 < file1-in.txt > file2-out.txt

# start server
./snc --key CSC574ISAWESOME -l 9999 > file1-out.txt < file2-in.txt


Here “file1-in.txt” is the file being transferred from client to server and the output of this transaction is “file1-out.txt”. The file being sent from server to client is “file2-in.txt” and the output of this transaction on client is “file2-out.txt”


The execution of this script also creates two logging files in the same directory with names “snc-server-debug.log” and “snc-client-debug.log”. These are additional debug files to keep track of all the transactions that are happening.


### Steps

* Client will read from stdin and send AES GCM protected data to instance running on server
* Server will read the file, decrypt, validate data and write to stdout
* Both instances should terminate connection when EOF is found, OR a keyboard interrupt

Additionally, netcat_final.py is attached that has the code with .py extension
