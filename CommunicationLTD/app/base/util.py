import hashlib
import binascii
import os
import smtplib
from passlib.hash import sha256_crypt
import ssl

def hash_pass(password):
   password_hased = sha256_crypt.encrypt(password)
   return password_hased


def verify_pass(provided_password, stored_password):
    return sha256_crypt.verify(provided_password,stored_password)


def verify_pass_length(provided_password,length):
    """Verify a provided password length"""
    if (len(provided_password)) >= length:
        return False
    else:
        return True


def verify_pass_with_dictionary(provided_password,dictionary):
    for word in dictionary:
        if word in provided_password:
            return word
    return "0"


def verify_pass_complexity(provided_password):
    SpecialSym =['!','@','#','$','%','^','&','*','(',')','-','_','+','=','','{','}','[',']']
    if not any(char.isdigit() for char in provided_password):
        return True
    if not any(char.isupper() for char in provided_password):
        return True
    if not any(char.islower() for char in provided_password):
        return True
    if not any(char in SpecialSym for char in provided_password):
        return True
    return False


def email_sender(reciver_email, message):
    
    smtp_server = "smtp.gmail.com"
    port = 465  # For SSL
    context = ssl.create_default_context()
    company_email = "comsltd12@gmail.com"
    company_email_pass = "comsLTD12.Com"
    
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(company_email, company_email_pass)
        server.sendmail(company_email, reciver_email, message)



