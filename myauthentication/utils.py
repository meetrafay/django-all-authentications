from django.core.mail import EmailMessage
import os

class Util:
  @staticmethod
  def send_email(data):
    email = EmailMessage(
      subject=data['subject'],
      body=data['body'],
      from_email=os.environ.get('EMAIL_FROM'),
      to=[data['to_email']]
    )
    email.send()
    
    
    
import random

def generate_otp(length=6):
    """
    Generate a random OTP (One-Time Password) of the specified length.
    By default, the length is set to 6 digits.
    """
    digits = "0123456789"
    otp = ""
    for _ in range(length):
        otp += random.choice(digits)
    return otp
