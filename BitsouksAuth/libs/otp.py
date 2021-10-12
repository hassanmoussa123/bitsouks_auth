import boto3
import math
import random
import os
from libs.sns import send_otp_sms
from libs.exceptions import RecordExists
import time
from boto3.dynamodb.conditions import Key
from libs.exceptions import TooMuchOtpRequests
dynamodb = boto3.resource('dynamodb', os.environ['REGION'])
def create_otp_record(phone_number):
    otp_table = dynamodb.Table(os.environ['OTP_TABLE_NAME'])
    try:
        if not check_if_record_exists(phone_number):
            otp = generateOTP()
            otp_table.put_item(
                Item={
                    'phone_number': phone_number,
                    'otp': otp,
                    'request_counter': 1,
                    'last_time_requested': int(time.time()),
                    # otp is valid for  30 minutes
                    'valid_until':  int(time.time()) + 30*60
                }
            )
            try:
                send_otp_sms(otp , phone_number)
            except Exception as e:
                raise e
        else:
            raise RecordExists('record already exists')
    except Exception as e:
        raise e

# function to generate OTP
def generateOTP():
    digits = "0123456789"
    OTP = ""
    for i in range(6):
        OTP += digits[math.floor(random.random() * 10)]
    return OTP
#Function that check if the record already exists
def check_if_record_exists(phone_number):
    otp_table = dynamodb.Table(os.environ['OTP_TABLE_NAME'])
    response = otp_table.query(
        KeyConditionExpression=Key('phone_number').eq(phone_number)
    )
    return len(response['Items'])!=0

def get_phone_otp(phone_number):
    try:
        otp_table = dynamodb.Table(os.environ['OTP_TABLE_NAME'])
        response = otp_table.query(
            KeyConditionExpression=Key('phone_number').eq(phone_number) 
        )
        if response['Items'][0].get('valid_until') < time.time():
            raise Exception('OTP is not valid, please try to send it again')
    except Exception:
        raise Exception('OTP is not valid, please try to send it again')
    return response['Items'][0].get('otp')

def get_phone_request_counter(phone_number):
    try:
        otp_table = dynamodb.Table(os.environ['OTP_TABLE_NAME'])
        response = otp_table.query(
            KeyConditionExpression=Key('phone_number').eq(phone_number)
        )
    except Exception:
        raise Exception('Request is not valid, please try to send it again')
    return response['Items'][0].get('request_counter')

def get_phone_last_time_requested(phone_number):
    try:
        otp_table = dynamodb.Table(os.environ['OTP_TABLE_NAME'])
        response = otp_table.query(
            KeyConditionExpression=Key('phone_number').eq(phone_number)
        )
    except Exception:
        raise Exception('Request is not valid, please try to send it again')
    return response['Items'][0].get('last_time_requested')


def resend_verification_code(phone_number):
    otp_table = dynamodb.Table(os.environ['OTP_TABLE_NAME'])
    otp = generateOTP()
    try:
        try:
            last_time_requested = get_phone_last_time_requested(phone_number)
            counter = get_phone_request_counter(phone_number)
            if counter < 5 and  int(time.time()) - int(last_time_requested) < 60:
                raise TooMuchOtpRequests('You should wait 60 second before next call')
            if counter >= 5 :
                interval_to_wait = 2.4**int(counter - 5)
                if int(time.time()) - int(last_time_requested) < int(interval_to_wait) *60 *60:
                    raise TooMuchOtpRequests('You should wait ' + str(int(interval_to_wait)) +  ' hours before next call')
        except Exception as e:
            raise e
        otp_table.update_item(
                    Key={
                            'phone_number': phone_number,
                        }, 
                    UpdateExpression= 'SET #request_counter = request_counter + :counter, #otp = :otp, #last_time_requested = :last_time_requested , #valid_until = :valid_until',  
                    ExpressionAttributeNames = {
                        '#otp': "otp",
                        '#request_counter': "request_counter",
                        '#last_time_requested': "last_time_requested",
                        '#valid_until': "valid_until"    
                    },
                    ExpressionAttributeValues = {
                        ':otp' : otp ,
                        ':counter': 1,
                        ':last_time_requested': int(time.time()),
                        ':valid_until':  int(time.time()) + 30*60
                    },
                )
        try:
            send_otp_sms(otp , phone_number)
        except Exception as e:
            raise e
    except Exception as e:
        raise e

    