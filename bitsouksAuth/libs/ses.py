import boto3
from botocore.exceptions import ClientError
import os


def send_email(email_details):
    sender = os.environ['BASE_EMAIL']
    recipient = email_details.get('recipient')
    subject = email_details.get('subject')
    body_text = (
        email_details.get('body'))
    body_html = """<html>
    <head></head>
    <body>
    <p>""" + email_details.get('body') + """</p>
    </body>
    </html>
                """
    charset = "UTF-8"
    client = boto3.client('ses', region_name=os.environ['REGION'])
    try:
        # Provide the contents of the email.
        client.send_email(
            Destination={
                'ToAddresses': [
                    recipient,
                ],
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': charset,
                        'Data': body_html,
                    },
                    'Text': {
                        'Charset': charset,
                        'Data': body_text,
                    },
                },
                'Subject': {
                    'Charset': charset,
                    'Data': subject,
                },
            },
            Source=sender,
        )
    # Display an error if something goes wrong.
    except ClientError as e:

        raise e


def send_already_exist_email(email):
    email_details = {
        'recipient': email,
        'subject' : "Important Notice : Someone is using your email to signup on our system",
        'body' : "Your email has been used for registration , this is considered as a notice\r\n"
    }
    try :
        send_email(email_details)
    except Exception as e:

        raise e

        
        
