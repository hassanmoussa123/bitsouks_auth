import json 
def http_response(status_code , message):
    return {
             "statusCode": status_code,
             "headers": {
                    "Content-Type": "application/json"
                },
             "body": json.dumps(message)
         }