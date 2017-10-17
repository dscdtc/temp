---
title: Fake Netcat
date: 2017-03-28 16:34:28
tags: [python,net tool]
categories: python
---
## Fake Netcat
<!--more-->
``` python
##!/usr/bin/env python
###__Author__ = "dscdtc"###
import 
import socket
import optparse
import threading
import subprocess

#socket.setdefaulttimeout(30)

# if we don't listen we are a client
def client_sender(buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # connect to target Host
        client.connect((target, port))
        if buffer:
            client.send(buffer)
        while 1:
            # Wite for data feedback
            recv_len = 1
            response = ''

            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data
                if recv_len:
                    break
            print response,
            #Wait for more input
            buffer = raw_input('<NC:#> ') + "\n"

            #Send command
            client.send(buffer)

    except Exception, e:
        print '[-] Error: %s\n[-] Exception Exiting...' % e
        client.close()
        exit(0)

# this is for incoming connections
def server_loop():
    global target
    global port

    server = socket.socket(socket.AF_INET,
                           socket.SOCK_STREAM)
    server.bind((target, port))
    server.listen(5)
    print 'Start listen on %s:%s ...\n' % (target, port)

    while 1:
        client_socket, addr = server.accept()
        print client_socket, addr
        # spin off a thread to handle our new client
        client_thread = threading.Thread(target=client_handler,
                                        args=(client_socket))
        client_thread.start()

# this runs a command and returns the output
def run_command(command):
    #command newline
    command = command.rstrip()
    #run the command and return result
    try:
        output = subprocess.check_output(
            command, stderr=subprocess.STDOUT, shell=True)
    except Exception, e:
        output = '[-] Error: %s\r\n[-] Failed to execute command!\r\n' % e

    #Send output
    return output

# this handles incoming client connections
def client_handler(client_socket):
    # this handles incoming client connections
    global upload
    global execute
    global is_command
    # check for upload
    if upload:
        client_socket.send('Uploading now...')
        # read in all of the bytes and write to our destination
        file_buffer = ''
        # keep reading data until none is available
        while 1:
            data = client_socket.recv(1024)
            if data:
                break
            else:
                file_buffer += data

        # now we take these bytes and try to write them out
        try:
            file_descriptor = open(upload, 'wb')
            file_descriptor = write(file_buffer)
            file_descriptor.close

            # acknowledge that we wrote the file out
            client_socket.send('Successfully saved file to %s\r\n' % \
                               upload)
        except:
            client_socket.send('Failed to save file to %s\r\n' % \
                               upload)

    # check for command execution
    if execute:
        client_socket.send('Executing now...')
        # run the command
        output = run_command(execute)
        client_socket.send(output)

    # go into another loop if a command shell was requested
    if is_command is True:
        client_socket.send('Command is running...\n')
        while 1:
            # show a simple prompt
            # now we receive until we see a linefeed (enter key)
            cmd_buffer = ''
            while '\n' not in cmd_buffer:
                print '.',
                cmd_buffer += client_socket.recv(1024)
                # we have a valid command so execute it and send back the results
                response = run_command(cmd_buffer)
                # send back the response
                client_socket.send(response)

def main():
    global port
    global target
    global upload
    global execute
    global is_listen
    global is_command

    example = '''\r\nExamples:
    Server: netcat -l -p 9999 -c
    Client: netcat -t localhost -p 9999
    netcat.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe
    netcat.py -t 192.168.0.1 -p 5555 -l -e='cat etc/passwd'
    echo 'ABCDEFGHI' | netcat.py -t 192.168.11.12 -p 135 \r\n
    '''
    usage = "%prog -t <target host> -p <listen port> \n\
     -l <listen mod> -e <execute cmd|exe> \n\
     -c <cmd mod> -u <upload file>"
    parser = optparse.OptionParser(usage, version="%prog 1.0")
    # if no target here we listen all port
    parser.add_option('-t', dest='target',
                      type='string', default='0.0.0.0',
                      help='specify target host to listen on')
    parser.add_option('-p', dest='port',
                      type='int',
                      help='specify target port to listen on')
    parser.add_option('-l', dest='is_listen',
                      action='store_true', default=False,
                      help='listen on [host]:[port] for incoming connections')
    parser.add_option('-e', dest='execute',
                      type='string', default='',
                      help='execute the given file upon receivinga connection')
    parser.add_option('-c', dest='is_command',
                      action='store_true', default=False,
                      help='initialize a command shell')
    parser.add_option('-u', dest='upload',
                      type='string', default='',
                      help='upon receiving connection upload a file and write to [destination]')
    (options, args) = parser.parse_args()

    target = options.target         #d
    port = options.port             #s
    is_listen = options.is_listen   #c
    execute = options.execute       #d
    is_command = options.is_command #t
    upload = options.upload         #c

    print "\r\nWelcome to dscdtc's <Fake Netcat Tool>\r\n"

    # are we going to listen or just send data from stdin
    if not is_listen and port and len(target):
        # read in the buffer from the commandline
        # this will block, so send CTRL-D
        # if not sending input to stdin
        buffer = sys.stdin.read()
        # send data off
        client_sender(buffer)

    elif is_listen and port is not None:
        server_loop()

    else:
        print parser.print_help()
        print example
        sys.exit(0)

if __name__ == '__main__':
    __Author__ = "dscdtc"
    main()
```
