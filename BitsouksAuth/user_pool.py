import boto3
import os
import base64
import binascii
import boto3
import datetime as dt
import hashlib
from libs.aes import DecryptPassword
import srp
from requests import get
import dateutil.parser
import hmac
import traceback
from warrant import aws_srp
from warrant.aws_srp import AWSSRP
# Import QRCode from pyqrcode
import pyqrcode
from pyqrcode import QRCode
from models.devices import create_device_record
from models.devices import get_device_by_ip_address

cognito_client = boto3.client('cognito-idp', os.environ['REGION'])
def get_user_by_email(email) :
    resp = {}
    try:
        resp = cognito_client.list_users(
            UserPoolId=os.environ['COGNITO_POOL_ID'],
            Filter=f"email='{email}'"
        )
        if len(resp.get('Users')) < 1 :
            raise Exception('No users founded')  
    except Exception as e:
        raise e 
    return resp.get('Users')[0].get('Attributes')
def check_if_user_email_exists(email):
    exists = False
    try:
        resp = cognito_client.list_users(
            UserPoolId=os.environ['COGNITO_POOL_ID'],
            Filter=f"email='{email}'"
        )
        exists = len(resp.get('Users')) > 0
    except Exception as e:
        exists = False

    return exists
def check_if_user_phone_number_exists(phone_number):
    exists = False
    try:
        resp = cognito_client.list_users(
            UserPoolId=os.environ['COGNITO_POOL_ID'],
            Filter=f"phone_number='{phone_number}'"
        )
        exists = len(resp.get('Users')) > 0
    except Exception as e:
        exists = False

    return exists
def sign_up_user(user):
    try:
        signup_response = cognito_client.sign_up(
            UserAttributes=[
                {
                    'Name': 'given_name',
                    'Value': user.get('first_name'),
                },
                {
                    'Name': 'family_name',
                    'Value': user.get('last_name'),
                },
            ],
            ClientId=os.environ['COGNITO_USER_CLIENT_ID'],
            Username=user.get('email'),
            Password=user.get('password'),
        )
        try :
            add_user_to_group(user.get('email') , user.get('user_type'))
        except Exception as e :

            raise Exception("error during registering user on cognito", e)
        return signup_response
    except Exception as e:

        raise Exception("error during registering user on cognito", e)
def confirm_email(email, confirmation_code):
    try:
        confirm_email_response = cognito_client.confirm_sign_up(
            ClientId=os.environ['COGNITO_USER_CLIENT_ID'],
            Username=email,
            ConfirmationCode=confirmation_code
        )
        return confirm_email_response
    except cognito_client.exceptions.CodeMismatchException as e:
        raise e
    except cognito_client.exceptions.LimitExceededException as e:
        raise e
    except cognito_client.exceptions.TooManyRequestsException as e:
        raise e
    except cognito_client.exceptions.TooManyFailedAttemptsException as e:
        raise e
    except Exception as e:
        raise e
def resend_confirmation_code(email):
    try:
        resend_confirmation_code_response = cognito_client.resend_confirmation_code(
            ClientId=os.getenv('COGNITO_USER_CLIENT_ID'),
            Username=email,
        )
        return resend_confirmation_code_response
    except cognito_client.exceptions.LimitExceededException as e:
        raise e
    except cognito_client.exceptions.TooManyRequestsException as e:
        raise e
    except cognito_client.exceptions.NotAuthorizedException as e:
        raise e
    except Exception as e:
        raise e
def phone_registration(user_details):
    try:
        response = cognito_client.admin_update_user_attributes(
            UserPoolId=os.environ['COGNITO_POOL_ID'],
            Username=user_details.get('email'),
            UserAttributes=[
                {
                    'Name': 'phone_number',
                    'Value': user_details.get('phone_number')
                },
                {
                    'Name': 'custom:country',
                    'Value': user_details.get('country')
                }
            ],
        )
        return response
    except cognito_client.exceptions.TooManyRequestsException as e:
        raise e
    except Exception as e:
        raise e
def add_company_data(company_details):
    try:
        response = cognito_client.admin_update_user_attributes(
            UserPoolId=os.environ['COGNITO_POOL_ID'],
            Username=company_details.get('email'),
            UserAttributes=[
                {
                    'Name': 'custom:company_name',
                    'Value': company_details.get('company_name')
                },
                {
                    'Name': 'custom:trading_volume',
                    'Value': company_details.get('trading_volume')
                }
            ],
        )
        return response
    except cognito_client.exceptions.TooManyRequestsException as e:
        raise e
    except Exception as e:
        raise e
def add_user_to_group(username , group_name):
    try:
        add_user_response = cognito_client.admin_add_user_to_group(
                    UserPoolId=os.environ['COGNITO_POOL_ID'],
                    Username=username,
                    GroupName=group_name
                )
        return add_user_response
    except Exception as e:
        raise e
def verify_user_phone(username):
    try:
        response = cognito_client.admin_update_user_attributes(
            UserPoolId=os.environ['COGNITO_POOL_ID'],
            Username=username,
            UserAttributes=[
                {
                    'Name': 'phone_number_verified',
                    'Value': 'true'
                }
            ],
        )
        return response
    except cognito_client.exceptions.TooManyRequestsException as e:
        raise e
    except Exception as e:
        raise e
def generate_hash_device(device_group_key, username):
    device_password = base64.standard_b64encode(os.urandom(40)).decode('utf-8')
    combined_string = '%s%s:%s' % (device_group_key, username, device_password)
    combined_string_hash = aws_srp.hash_sha256(combined_string.encode('utf-8'))
    salt = aws_srp.pad_hex(aws_srp.get_random(16))
    x_value = aws_srp.hex_to_long(aws_srp.hex_hash(salt + combined_string_hash))
    g = aws_srp.hex_to_long(aws_srp.g_hex)
    big_n = aws_srp.hex_to_long(aws_srp.n_hex)
    verifier_device_not_padded = pow(g, x_value, big_n)
    verifier = aws_srp.pad_hex(verifier_device_not_padded)
    device_secret_verifier_config = {
        "PasswordVerifier": base64.standard_b64encode(bytearray.fromhex(verifier)).decode('utf-8'),
        "Salt": base64.standard_b64encode(bytearray.fromhex(salt)).decode('utf-8')
    }
    return device_password, device_secret_verifier_config
def init_auth(auth_details):
    decrypted_password = DecryptPassword(auth_details.get('safe_pass')).strip()
    try :
        aws = AWSSRP(username=auth_details.get('email'), password=decrypted_password, pool_id=os.environ['COGNITO_POOL_ID'],
                        client_id=os.environ['COGNITO_USER_CLIENT_ID'] , client=cognito_client)
        auth_init = cognito_client.admin_initiate_auth(
        AuthFlow='USER_SRP_AUTH',
        AuthParameters={
            'USERNAME': auth_details.get('email'),
            'SRP_A': aws_srp.long_to_hex(aws.large_a_value),
        },
        ClientId=os.environ['COGNITO_USER_CLIENT_ID'],
        UserPoolId=os.environ['COGNITO_POOL_ID'],
        )
        cr = aws.process_challenge(auth_init['ChallengeParameters'])
        response = cognito_client.respond_to_auth_challenge(
            ClientId=os.environ['COGNITO_USER_CLIENT_ID'],
            ChallengeName=auth_init['ChallengeName'],
            ChallengeResponses=cr
        )   
        return response
    except Exception as e :
        raise e
def get_trusted_devices(access_token):
    try:
        response = cognito_client.list_devices(
                AccessToken=access_token,
                Limit=5,
        )
        return response
    except Exception as e:
        raise e
def check_if_device_is_trusted(device_key , devices):
    devices = devices['Devices']
    if len(devices) > 0 :
        for  i  in range(len(devices)):
            if devices[i]['DeviceKey'] == device_key :
                return True
    return False
def full_authentication_flow(authentication_data):
    try :
        authentication_response = init_auth(authentication_data)
        if "AuthenticationResult" in authentication_response : # No MFA Activated
                device_key =  get_device_by_ip_address(get('https://api.ipify.org').text)
                trusted_devices =get_trusted_devices(authentication_response['AuthenticationResult']["AccessToken"])
                if not check_if_device_is_trusted(device_key , trusted_devices ):
                    challenge = {
                            "ChallengeRequired": True,
                            'ChallengeName': "EMAIL_VERIFICATION",
                            'CODE_DELIVERY_DESTINATION':  "EMAIL",
                            'authentication-data': authentication_response
                            }
                    device_group_key =  authentication_response['AuthenticationResult']['NewDeviceMetadata']['DeviceGroupKey']
                    _, device_secret_verifier_config = generate_hash_device(device_group_key, authentication_data.get('email'))
                    challenge['DeviceSecretVerifierConfig'] =  device_secret_verifier_config,
                    verify_email(authentication_response['AuthenticationResult']['AccessToken'])    
                    return challenge
                else :
                    authentication_response['ChallengeRequired'] = False
                    return authentication_response
        else:
            challenge = {
                "ChallengeRequired":True,
                'ChallengeName' : authentication_response['ChallengeName'],
                'Session' :  authentication_response['Session'],
                'Medium' :  authentication_response['ChallengeParameters']['CODE_DELIVERY_DELIVERY_MEDIUM'],
                'CODE_DELIVERY_DESTINATION' :  authentication_response['ChallengeParameters']['CODE_DELIVERY_DESTINATION'],
            }
            return challenge
    except Exception as e :
        raise e
def respond_to_challenge(challenge_response):
    try : 
        response = cognito_client.admin_respond_to_auth_challenge(
            UserPoolId=os.environ['COGNITO_POOL_ID'],
            ClientId=os.environ['COGNITO_USER_CLIENT_ID'],
            ChallengeName = challenge_response.get('challenge_name'),
            Session = challenge_response.get('session'),
            ChallengeResponses = {
                'SMS_MFA_CODE' : challenge_response.get('verification_code'),
                'USERNAME' : challenge_response.get('email')
            }
        )
        device_key = response['AuthenticationResult']['NewDeviceMetadata']['DeviceKey']
        device_group_key =  response['AuthenticationResult']['NewDeviceMetadata']['DeviceGroupKey']
        _, device_secret_verifier_config = generate_hash_device(device_group_key, challenge_response.get('email'))
        response['DeviceSecretVerifierConfig'] =  device_secret_verifier_config,
        return response
    except Exception as e:
        raise e
def verify_email(access_token):
    try :  
        cognito_client.get_user_attribute_verification_code(
            AccessToken=access_token,
            AttributeName='email',
        )
    except Exception as e :
        raise e
def respond_to_email_challenge(access_token , code):
    try : 
        cognito_client.verify_user_attribute(
            AccessToken=access_token,
            AttributeName='email',
            Code=code
        )
    except Exception as e :
        raise e
def trust_device(device_details ):
    try :
        cognito_client.confirm_device(
            AccessToken= device_details.get('access_token'),
            DeviceKey= device_details.get('device_key'),
            DeviceName = 'device_' + device_details.get('email'), 
            DeviceSecretVerifierConfig={
                'PasswordVerifier':  device_details.get('device_password_verifier'),
                'Salt': device_details.get('device_salt')
            },
        )
        create_device_record(device_details)
    except Exception as e :
        raise e
def forget_password_flow(email) :
    try:
        resp = cognito_client.forgot_password(
            ClientId = os.environ['COGNITO_USER_CLIENT_ID'], 
            Username = email
        )
        return resp 
    except Exception as e:
        raise e 
def confirm_forget_password(email , confirmation_code , password):
    try:
        resp = cognito_client.confirm_forgot_password(
            ClientId = os.environ['COGNITO_USER_CLIENT_ID'], 
            Username = email,
            ConfirmationCode = confirmation_code,
            Password = password
        )
        return resp 
    except Exception as e:
        raise e 
def associate_totp_software(access_token):
    try :
        response = cognito_client.associate_software_token(
            AccessToken=access_token,
        )
        if 'SecretCode' in response :
            qr_image_url = 'https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Bitsouks?secret=' + response['SecretCode']  + '&issuer=Bitsouks'
            response['QrCode'] = qr_image_url
        return response
    except Exception as e:
        raise e 
def verify_software_token(access_token , user_code) :
    try :
        response = cognito_client.verify_software_token(
                AccessToken=access_token,
                UserCode=user_code,
        )
        return response
    except Exception as e:
        raise e 
def enable_totp_mfa(access_token):
    try :
         r= cognito_client.set_user_mfa_preference(
                SoftwareTokenMfaSettings={
                    'Enabled': True,
                    'PreferredMfa': False
                },
                AccessToken=access_token
            )
    except Exception as e:
        raise e 
def enable_sms_mfa(access_token):
    try :
         cognito_client.set_user_mfa_preference(
                 SMSMfaSettings={
                    'Enabled': True,
                    'PreferredMfa': False
                },
                AccessToken=access_token
            )
         
    except Exception as e:
        raise e 
def disable_totp_mfa(access_token):
    try :
         cognito_client.set_user_mfa_preference(
                SoftwareTokenMfaSettings={
                    'Enabled': False,
                    'PreferredMfa': False
                },
                AccessToken=access_token
            )
    except Exception as e:
        raise e 
def disable_sms_mfa(access_token):
    try :
         cognito_client.set_user_mfa_preference(
                 SMSMfaSettings={
                    'Enabled': False,
                    'PreferredMfa': False
                },
                AccessToken=access_token
            )
    except Exception as e:
        raise e
def forget_device(access_token , device_key):
    try :    
        cognito_client.forget_device(
            AccessToken=access_token,
            DeviceKey=device_key
        )  
    except Exception as e:
        raise e   
def change_user_password(previous_password , proposed_password , access_token):
    try :    
        cognito_client.change_password(
            PreviousPassword=previous_password,
            ProposedPassword=proposed_password,
            AccessToken=access_token
        )
    except Exception as e:
        raise e
def update_email(old_email , new_email , access_token ):  
    cognito_client.update_user_attributes(
    AccessToken=access_token,
    Username=old_email,
    UserAttributes=[
        {
            'Name': 'email',
            'Value': new_email
        },
    ],
    ) 
def update_phone(email, phone_number , access_token ):  
    cognito_client.update_user_attributes(
    AccessToken=access_token,
    Username=email,
    UserAttributes=[
        {
            'Name': 'phone_number',
            'Value': phone_number
        },
    ],
) 
def admin_disable_totp_mfa(email):
    try :
         cognito_client.admin_set_user_mfa_preference(
                SoftwareTokenMfaSettings={
                    'Enabled': False,
                    'PreferredMfa': False
                },
                Username=email,
                UserPoolId=os.environ['COGNITO_POOL_ID']
            )
    except Exception as e:
        raise e 
def admin_disable_sms_mfa(email):
    try :
         cognito_client.admin_set_user_mfa_preference(
                 SMSMfaSettings={
                    'Enabled': False,
                    'PreferredMfa': False
                },
                Username=email,
                UserPoolId=os.environ['COGNITO_POOL_ID']
            )
    except Exception as e:
        raise e
