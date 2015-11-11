"""
*** Author:         Laurent Hayez
*** Date:           30 october 2015
*** Description:    Implementation of a SMTP gateway to filter emails before sending them to the real SMTP
***                 server. From the user perspective, the gateway acts as an SMTP server.
***                 Upgrade: passes the email to an anti-virus (clamXav here) before sending it to check if
***                          there is any virus.
***                 Supported:  Eicar test string in message,
***                             Eicar test file as attachment,
***                             Eicar test file zipped once/twice as attachment
"""
import asyncore
import smtpd
import smtplib
import re
import os

import pyclamd

# Constants
import json

smtp_server = 'smtp.live.com'
# Need to use port 587 instead of 25. The UniNe firewall seems to block outgoing mail on that port.
smtp_port = 587


# SMTP Gateway
class SMTPGateway(smtpd.SMTPServer):
    # Override process_message from smtpd.STMPServer class
    def process_message(self, peer, mailfrom, rcpttos, data):
        print('\n\nThe server is processing your email...\n\n')
        print(data, '\n\n')
        forbidden_words = self.check_message(data)
        virus = self.check_for_virus(data)
        if len(forbidden_words) > 0 or virus:
            if len(forbidden_words) > 0:
                print('The following forbidden words have been found:')
                print(forbidden_words)
                print('Not sending email.')
            if virus:
                print('I caught you trying to send a virus! This is bad, and you should feel bad!\n')
                print('Virus(es) found: ', virus)
                print('I won\'t send your email.')
        else:
            # Forwarding email to the real smtp server
            print('No forbidden word or virus found. Forwarding email\n\n')
            remote_server = smtplib.SMTP(smtp_server, smtp_port)
            # As we use port 587, we need to start TLS connection and need authentication
            remote_server.starttls()
            identifiers = json.loads(open("ident.json").read())
            remote_server.login(identifiers['login'], identifiers['pwd'])
            remote_server.set_debuglevel(True)  # show communication with the server
            try:
                remote_server.sendmail(mailfrom, rcpttos, data)
            finally:
                remote_server.quit()
        return

    @staticmethod
    def check_message(data):
        forbidden_words_file = open('forbidden_words.txt', 'r', encoding='utf-8')
        forbidden_words = []
        # Read forbidden_words.txt line by line (one word per line)
        for current_word in forbidden_words_file:
            # as we read line by line, the word is of the form 'word\n' => remove \n
            if re.search('\n', current_word):
                current_word = current_word[:len(current_word) - 1]

            # Search for occurrences of the current word in the email
            # Note: with that regex, if 'con' is a forbidden word, 'connection' is a forbidden word.
            if re.search(current_word, data):
                forbidden_words.append(current_word)

        # Close file
        forbidden_words_file.close()

        # Return the list of forbidden words found (can be empty)
        return forbidden_words

    @staticmethod
    def check_for_virus(data):
        # Writing data to a file for scanning
        path = '/tmp/file_to_scan.txt'
        file_to_scan = open(path, 'w+')
        file_to_scan.write(str(data))
        file_to_scan.close()

        # Initialize pyclamd socket
        pyclamd.init_unix_socket('/tmp/clamd.socket')

        # Scanning file
        virus_found = pyclamd.scan_file(path)

        # Remove the file that was to scan
        os.remove(path)

        return virus_found


server = SMTPGateway(('127.0.0.1', 1025), (smtp_server, smtp_port), None)
asyncore.loop()
