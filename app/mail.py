from flask_mail import Message  
from app import app, mail

def send_mail(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender= app.config['DIGISIGN_MAIL_SENDER'])
    mail.send(msg)