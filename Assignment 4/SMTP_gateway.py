"""
*** Author:         Laurent Hayez
*** Date:           30 october 2015
*** Description:    Implementation of a SMTP gateway to filter emails before sending them to the real SMTP
***                 server. From the user perspective, the gateway acts as an SMTP server.
"""
import asyncore
import smtpd
import smtplib
import re

# Constants
smtp_server = 'smtp.live.com'
# Need to use port 587 instead of 25. The UniNe firewall seems to block outgoing mail on that port.
smtp_port = 587


# SMTP Gateway
class SMTPGateway(smtpd.SMTPServer):
    # Override process_message from smtpd.STMPServer class
    def process_message(self, peer, mailfrom, rcpttos, data):
        print('\n\nThe server is processing your email...\n\n')
        forbidden_words = self.check_message(data)
        if len(forbidden_words) > 0:
            print('The following forbidden words have been found:')
            print(forbidden_words)
            print('Not sending email.')
        else:
            # Forwarding email to the real smtp server
            print('No forbidden word found. Forwarding email\n\n')
            remote_server = smtplib.SMTP(smtp_server, smtp_port)
            # As we use port 587, we need to start TLS connection and need authentication
            remote_server.starttls()
            # Add email and password here :)
            remote_server.login('foo@bar.com', '*****')
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


server = SMTPGateway(('127.0.0.1', 1025), (smtp_server, smtp_port), None)
asyncore.loop()
