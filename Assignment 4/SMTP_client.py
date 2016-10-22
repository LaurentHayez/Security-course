import smtplib
import email.utils
from email.mime.text import MIMEText

# Create the message
msg = MIMEText('Testing stmp protocol.')
msg['To'] = email.utils.formataddr(('Recipient', 'l.hayez@hotmail.com'))
msg['From'] = email.utils.formataddr(('Author', 'l.hayez@hotmail.com'))
msg['Subject'] = 'Test subject'

server = smtplib.SMTP('127.0.0.1', 1025)
# server.set_debuglevel(True) # show communication with the server
try:
    server.sendmail('l.hayez@hotmail.com', ['l.hayez@hotmail.com'], msg.as_string())
finally:
    server.quit()
