#!/usr/bin/env python3

"""
Copyright (c) 2019 hjltu@ya.ru

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

About:
    proxy.py is Multi-threaded UDP Server

Source project:
    https://github.com/pathes/fakedns
    Author:Patryk Hes
    License: MIT

Documentation:
    DNS Specification:
        https://www.ietf.org/rfc/rfc1035.txt

What it does:
    Server respond to DNS,
    if domain on the blacklist the response is "not resolved"
    if not, the remote server is requested

Usage:
    sudo ./run.sh proxy2.py

    dig test.test @localhost

"""

import sys
import socket
import socketserver

# blacklist
from config import blc


REMOTE_ADDR = '8.8.8.8'
REMOTE_PORT = 53
LOCAL_PORT = 53
DNS_HEADER_LENGTH = 12


class DNSHandler(socketserver.BaseRequestHandler):

    def handle(self):

        """
        find question section and domain
        check if domain in blacklist and
        give answer "not resolved" or 
        send UDP message to remote server
        """

        _socket = self.request[1]
        data = self.request[0].strip()

        # If request doesn't even contain full header, don't respond.
        if len(data) < DNS_HEADER_LENGTH:
            return

        # Try to read questions - if they're invalid, don't respond.
        try:
            all_questions = self.dns_extract_questions(data)
        except IndexError:
            return

        # Filter only those questions, which have QTYPE=A and QCLASS=IN
        # TODO this is very limiting, remove QTYPE filter in future, handle different QTYPEs
        accepted_questions = []
        for question in all_questions:
            name = str(b'.'.join(question['name']), encoding='UTF-8')
            if question['qtype'] == b'\x00\x01' and question['qclass'] == b'\x00\x01':
                accepted_questions.append(question)
                print('\033[32m{}\033[39m'.format(name))
            else:
                print('\033[31m{}\033[39m'.format(name))

        # Check blacklist and choose server for answer
        response=None
        # Custom message
        if name in blc:
            response = (
                self.dns_response_header(data) +
                self.dns_response_questions(accepted_questions) +
                self.dns_response_answers(accepted_questions)
            )
        # Ask remote server
        else:
            server = (REMOTE_ADDR, REMOTE_PORT)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(server)
            sock.send(self.request[0])
            response = sock.recv(1024)

        _socket.sendto(response, self.client_address)

    def dns_extract_questions(self, data):
        """
        Extracts question section from DNS request data.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        questions = []
        # Get number of questions from header's QDCOUNT
        n = (data[4] << 8) + data[5]
        # Where we actually read in data? Start at beginning of question sections.
        pointer = DNS_HEADER_LENGTH
        # Read each question section
        for i in range(n):
            question = {
                'name': [],
                'qtype': '',
                'qclass': '',
            }
            length = data[pointer]
            # Read each label from QNAME part
            while length != 0:
                start = pointer + 1
                end = pointer + length + 1
                question['name'].append(data[start:end])
                pointer += length + 1
                length = data[pointer]
            # Read QTYPE
            question['qtype'] = data[pointer+1:pointer+3]
            # Read QCLASS
            question['qclass'] = data[pointer+3:pointer+5]
            # Move pointer 5 octets further (zero length octet, QTYPE, QNAME)
            pointer += 5
            questions.append(question)
        return questions

    def dns_response_header(self, data):
        """
        Generates DNS response header.
        See http://tools.ietf.org/html/rfc1035 4.1.1. Header section format.
        """
        header = b''
        # ID - copy it from request
        header += data[:2]
        # QR     1    response
        # OPCODE 0000 standard query
        # AA     0    not authoritative
        # TC     0    not truncated
        # RD     0    recursion not desired
        # RA     0    recursion not available
        # Z      000  unused
        # RCODE  0000 no error condition
        header += b'\x80\x00'
        # QDCOUNT - question entries count, set to QDCOUNT from request
        header += data[4:6]
        # ANCOUNT - answer records count, set to QDCOUNT from request
        header += data[4:6]
        # NSCOUNT - authority records count, set to 0
        header += b'\x00\x00'
        # ARCOUNT - additional records count, set to 0
        header += b'\x00\x00'
        return header

    def dns_response_questions(self, questions):
        """
        Generates DNS response questions.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        sections = b''
        for question in questions:
            section = b''
            for label in question['name']:
                # Length octet
                section += bytes([len(label)])
                section += label
            # Zero length octet
            section += b'\x00'
            section += question['qtype']
            section += question['qclass']
            sections += section
        return sections

    def dns_response_answers(self, questions):
        """
        Generates DNS response answers.
        See http://tools.ietf.org/html/rfc1035 4.1.3. Resource record format.
        """
        records = b''
        for question in questions:
            record = b''
            for label in question['name']:
                # Length octet
                record += bytes([len(label)])
                record += label
            # Zero length octet
            record += b'\x00'
            # TYPE = 16 (TXT)
            # TODO QTYPE values set is superset of TYPE values set, handle different QTYPEs, see RFC 1035 3.2.3.
            record += b'\x00\x10'

            # CLASS - just copy QCLASS
            # TODO QCLASS values set is superset of CLASS values set, handle at least * QCLASS, see RFC 1035 3.2.5.
            record += question['qclass']
            # TTL - 32 bit unsigned integer. Set to 0 to inform, that response
            # should not be cached.
            record += b'\x00\x00\x00\x00'

            # RDLENGTH - 16 bit unsigned integer, length of RDATA field.
            # In case of QTYPE=TXT and QCLASS=IN, RDLENGTH=13.
            record += b'\x00\x0d'
            # RDATA - in case of QTYPE=TXT and QCLASS=IN, it's text.
            record += b'\x0c'
            record += b'not resolved'

            records += record
        return records

if __name__ == '__main__':
    # Create multithread server, CTRL+C to EXIT
    host, port = '', LOCAL_PORT
    server = socketserver.ThreadingUDPServer((host, port), DNSHandler)
    print('\033[36mStarted DNS server.\033[39m')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
sys.exit(0)
