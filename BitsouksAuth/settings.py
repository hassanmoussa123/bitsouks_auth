import boto3
import os 
from boto3.dynamodb.conditions import Key
dynamodb = boto3.resource('dynamodb', os.environ['REGION'])
def check_if_registration_enabled():
    try:
        settings_table = dynamodb.Table(os.environ['SETTING_TABLE_NAME'])
        response = settings_table.query(
            KeyConditionExpression=Key('key').eq('registration_enabled')
        )
    except Exception:
        return False
    if len(response['Items']) > 0:
        return response['Items'][0].get('value') == 'true'
    return False
