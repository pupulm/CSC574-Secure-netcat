#!/usr/bin/env python3

import sys
import socket
import time
import logging
import socketserver
import argparse
import select
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import json
import os

# detach to get binary data
stdin = sys.stdin.detach()

JSON_KEYS_COMMON = ['nonce', 'salt', 'tag', 'ciphertext']
LOG_FORMAT = '%(levelname)s > (%(asctime)s): %(message)s'
LOG_LEVEL = logging.DEBUG

def create_socket(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return sock


def create_server(host, port):
    sock = create_socket(host, port)
    sock.bind((host, port))
    sock.listen(5)
    return sock


def connect_client(host, port):
    sock = create_socket(host, port)
    sock.connect((host, port))
    return sock

# sends encrypted content to the provided socket
def post_content(sock, content, key):
    enc_content = encrypt(key, content)
    sock.sendall(enc_content)
    time.sleep(0.1)

# obtain 1024 bytes of content from sock
def get_content(sock):
    return sock.recv(1024)

# base64 encode
def b64encode(s):
    return base64.b64encode(s).decode('utf-8')

# base64 decode
def b64decode(s):
    return base64.b64decode(s)


def create_cipher(key, nonce, salt):
    key = PBKDF2(key, salt, dkLen=32, count=1000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    return cipher

# Encrypts data with given key and creates JSON cipher data
def encrypt(key, plaintext):
    nonce = get_random_bytes(12)
    salt = get_random_bytes(12)
    cipher = create_cipher(key, nonce, salt)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    json_keys = JSON_KEYS_COMMON
    json_values = [nonce, salt, tag, ciphertext]
    json_values_b64 = map(b64encode, json_values)
    json_data = dict(zip(json_keys, json_values_b64))
    return str.encode(json.dumps(json_data)) + b'\n'

# Decrypts JSON cipher data to plain text
def decrypt(data, key):
    try:
        json_input = json.loads(data)
        json_keys = JSON_KEYS_COMMON
        json_data = {k: b64decode(json_input[k]) for k in json_keys}
        cipher = create_cipher(key, json_data['nonce'], json_data['salt'])
        plaintext = cipher.decrypt_and_verify(
            json_data['ciphertext'], json_data['tag'])
        return plaintext.decode()
    except:
        logging.debug('failed to decrypt ' + str(data))


# read a line from stdin
def read_stdin():
    return stdin.readline()

def close_write(sock):
    sock.shutdown(socket.SHUT_WR)
    time.sleep(.5)

# decrypt content line by line and print to stdout
def decrypt_and_print(content, key):
    logging.debug(content)
    lines = content.split(b'\n')
    for line in lines:
        if line:
            plaintext = decrypt(line, key)
            # sys.stdout.write(plaintext)
            print(plaintext, end='')


# whem connection ends print content and exit
def handle_close(content, key):
    decrypt_and_print(content, key)
    exit(0)


# start server
def run_server(host, port, key):
    server = create_server(host, port)
    # inputs to select from
    inputs = [server]
    outputs = []
    
    # we'll append received data to this string
    content = b''

    reading_done = False
    writing_done = False
    
    # Check if stdin has data (True if empty)
    
    try:
        while 1:
            # Wait for I/O completion
            infds, outfds, _ = select.select(inputs, outputs, [], 3)
            for fd in infds:
                if fd is server:
                    # incoming connection, accept and add to select inputs and outputs
                    client_sock, client_addr = fd.accept()
                    logging.debug(f'connecting from {client_addr}')
                    inputs.append(client_sock)

                    # Check if stdin has data
                    if not os.isatty(0):
                        outputs.append(client_sock)
                    else:
                        writing_done = True
                        close_write(client_sock)
                else:
                    logging.info('server receiving')
                    data = get_content(fd)
                    # check for end of data
                    if not data:
                        inputs.remove(fd)
                        reading_done = True
                    else:
                        content += data
                        logging.info(f'appending {data}')

            for fd in outfds:
                logging.info('server posting')
                # read from stdin and send to client socket
                data = read_stdin()
                logging.info(f'stdin > {data}, {bool(data)}')
                # write if there is data
                if data:
                    post_content(fd, data, key)
                else:
                    outputs.remove(fd)
                    close_write(fd)
                    writing_done = True
            logging.info(f'reading {reading_done}, writing {writing_done}')
            if reading_done and writing_done:
                handle_close(content, key)
    except KeyboardInterrupt:
        handle_close(content, key)


# run client
def run_client(host, port, key):
    client = connect_client(host, port)
    inputs = [client]
    outputs = []
    content = b''
    reading_done = False
    writing_done = False
    logging.info(f'server tty {stdin.isatty()}')
    if os.isatty(0):
        writing_done = True
        close_write(client)
    else:
        outputs = [client]
    try:
        while 1:
            # Wait for I/O completion
            infds, outfds, _ = select.select(inputs, outputs, [], 3)
            for fd in infds:
                logging.info('client receiving')
                data = get_content(fd)
                if data:
                    content += data
                    logging.info(data)
                else:
                    reading_done = True
            for fd in outfds:
                data = read_stdin()
                logging.info(f'stdin > {data}, {bool(data)}')
                if not data:
                    outputs.remove(fd)
                    # once writing is done, close write socket
                    fd.shutdown(socket.SHUT_WR)
                    time.sleep(.5)
                    writing_done = True
                else:
                    post_content(fd, data, key)

            logging.info(f'reading {reading_done}, writing {writing_done}')
            if reading_done and writing_done:
                handle_close(content, key)
    except KeyboardInterrupt:
        handle_close(content, key)


def main():
    parser = argparse.ArgumentParser("Secure netcat")
    parser.add_argument("--key", "-k", help="Key",
                        type=str, required=True)
    parser.add_argument('hostinfo', type=str, nargs='+', help='host port')
    parser.add_argument(
        "--listen", "-l", help="Start in server mode", default=False, action="store_true")
    args = parser.parse_args()
    hostinfo = args.hostinfo

    if len(hostinfo) > 2:
        sys.stderr.write("Positional argument hostinfo should be in format: host port.\nOnly arguments allowed")
        exit(0)

    host = None
    port = None

    if len(hostinfo) == 2:
        host = hostinfo[0]
        port = int(hostinfo[1])
    elif len(hostinfo) == 1:
        port = int(hostinfo[0])
        host = 'localhost'

    if args.key and args.listen:
        logging.basicConfig(filename='snc-server-debug.log',
                            level=LOG_LEVEL, format=LOG_FORMAT)
            
        run_server(host, port, args.key)

    elif args.key and not args.listen:
        logging.basicConfig(filename='snc-client-debug.log',
                            level=LOG_LEVEL, format=LOG_FORMAT)
        run_client(host, port, args.key)
    else:
        print("Invalid arguments provided")

if __name__ == "__main__":
    main()
