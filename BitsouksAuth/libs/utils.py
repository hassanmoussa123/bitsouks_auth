import secrets
import string
def generate_random_password():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return  'bitsouks2'.join(secrets.choice(alphabet) for i in range(9))

def get_index_number(array_of_dict , indicator):
    for i in range(len(array_of_dict)):
        if array_of_dict[i].get('Name') == indicator:
            return i