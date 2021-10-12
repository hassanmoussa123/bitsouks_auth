import boto3
import os
from libs.sns import send_otp_sms
from libs.exceptions import RecordExists
import time
from boto3.dynamodb.conditions import Key
dynamodb = boto3.resource('dynamodb', os.environ['REGION'])
def create_device_record(device_detals):
    otp_table = dynamodb.Table(os.environ['DEVICES_TABLE_NAME'])
    try:       
        otp_table.put_item(
            Item={
                'device_key': device_detals.get('device_key'),
                'ip_address': device_detals.get('ip_address'),
                'device_name': device_detals.get('device_name') 
            }
        )
    except Exception as e:
        raise e

def get_device_by_ip_address(ip_address):
    try:
        otp_table = dynamodb.Table(os.environ['DEVICES_TABLE_NAME'])
        response = otp_table.query(
            KeyConditionExpression=Key('ip_address').eq(ip_address)
        )
        if len(response['Items']) < 1 :
            return ''
    except Exception as e :
        raise e
    return response['Items'][0].get('device_key')
