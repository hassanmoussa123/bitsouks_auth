import requests
import json 
import os
def verifyRecaptcha(recaptcha_token):
    payload = {
               'secret' : os.environ['GOOGLE_RECAPTCHA_SECRET'] , 
               'response' : recaptcha_token,
              }
    try:
        resp = requests.post(url = "https://www.google.com/recaptcha/api/siteverify", data = json.dumps(payload) , timeout=5)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.HTTPError, requests.exceptions.ReadTimeout, requests.exceptions.Timeout, ConnectionError) as e:
        raise e
    return json.loads(resp.text).get('success')

    
