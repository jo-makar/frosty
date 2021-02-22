import email.mime.text
import json
import os
import smtplib
from typing import Union


def send(to:Union[str,None], subject:str, body:str, html:bool=False) -> None:
    with open(os.path.join(os.path.dirname(__file__), 'gmail.json')) as file:
        creds = json.load(file)
    username = creds['username']
    assert username.endswith('@gmail.com')
    password = creds['password']

    if to is None:
        to = creds['default']

    if html:
        m = email.mime.text.MIMEText(body, 'html')
        m['Subject'] = subject
        m['From'] = username
        m['To'] = to
        mail = m.as_string()
    else:
        mail = f'Subject: {subject}\nFrom: {username}\nTo: {to}\n\n{body}'

    smtp = smtplib.SMTP('smtp.gmail.com', 587)
    smtp.ehlo()
    smtp.starttls()
    smtp.login(username, password)
    smtp.sendmail(username, to, mail)
    smtp.close()
