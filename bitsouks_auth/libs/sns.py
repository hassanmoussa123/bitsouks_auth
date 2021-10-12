import boto3
import os

def send_otp_sms(otp , phone_number):
    try:   
        sns = boto3.client('sns')
        number = phone_number
        sns.publish(PhoneNumber = number, Message='The verification code to your account is: ' + str(otp))
    except Exception as e:
        raise e
def send_already_exists_sms(phone_number):
    try:  
        sns = boto3.client('sns')
        number =  phone_number
        sns.publish(PhoneNumber = number, Message='Your phone number is already registred, someone is trying to use your phone number')
    except Exception as e:
        raise e