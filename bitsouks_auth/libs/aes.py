from Crypto.Cipher import AES
import base64
import re
import os 
key = os.environ['AES_ENCRYPTION_KEY']

def DecryptPassword(password):
    try :
        password_decoded = base64.b64decode(password)
        decipher = AES.new(key, AES.MODE_ECB)
        d = decipher.decrypt(password_decoded)
        password_decoded_final = re.split('\s+', re.sub(r"[\x00-\x1F\x7F]", ' ', d.decode("utf-8",'ignore')))        
        return  ' '.join(password_decoded_final)
    except Exception as e:
        raise e
    
