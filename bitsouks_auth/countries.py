import boto3
import os 
from boto3.dynamodb.conditions import Key
dynamodb = boto3.resource('dynamodb', os.environ['REGION'])
def check_if_country_enabled(country_name):
    try:
        countries_table = dynamodb.Table(os.environ['COUNTRIES_TABLE_NAME'])
        response = countries_table.query(
            KeyConditionExpression=Key('country_name').eq(country_name)
        )
    except Exception as e:
        print(e)
        return False
    if len(response['Items']) > 0:
        return response['Items'][0].get('enabled') == 'true'
    return False

