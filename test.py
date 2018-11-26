# from com.thumbsignin import AzureAuthConnector
# from com.thumbsignin.util import Util
import httplib
import urllib
import json
from datetime import datetime
from org.apache.commons.codec.binary import Base64
from java.lang import String

AZURE_TENANT_ID = 'c5bd07ef-f708-4577-84ce-e0e1faca9b8f'
AZURE_CLIENT_ID = '30408b60-ccdc-4533-852a-220e75a6633f'
AZURE_CLIENT_SECRET = 'WNbKiL0xj8PJkAk+LkdtQuUfhYjCNUFFJ94d1H2vHqw='
AZURE_USER_NAME = 'demo@ak1976hotmail.onmicrosoft.com'
AZURE_USER_ID = '57d47a0b-b834-4906-b60b-2bd177f6369e'
MICROSOFT_AUTHORITY_URL = 'login.microsoftonline.com'
AZURE_AD_GRAPH_RESOURCE_ENDPOINT = 'https://graph.windows.net'


def authenticate_user_in_azure(tenant_id, user_name, pwd, client_id, client_secret):
    post_params_json = {'resource': AZURE_AD_GRAPH_RESOURCE_ENDPOINT, 'client_id': client_id,
                        'client_secret': client_secret, 'username': user_name, 'password': pwd,
                        'grant_type': 'password', 'scope': 'openid'}
    post_params_url_encoded = urllib.urlencode(post_params_json)
    headers_json = {'Content-type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'}
    conn = httplib.HTTPSConnection(MICROSOFT_AUTHORITY_URL + ':443')
    relative_url = '/' + tenant_id + '/oauth2/token'
    conn.request('POST', relative_url, post_params_url_encoded, headers_json)
    response = conn.getresponse()
    # print response.status, response.reason
    azure_response = response.read()
    conn.close()
    print "Response Data: %s" % azure_response
    azure_response_json = json.loads(azure_response)
    if 'id_token' in azure_response_json:
        id_token = azure_response_json['id_token']
        id_token_array = String(id_token).split("\\.")
        id_token_payload = id_token_array[1]
        id_token_payload_str = String(Base64.decodeBase64(id_token_payload), 'UTF-8')
        return str(id_token_payload_str)
    else:
        return azure_response


print "Start Time: %s" % datetime.now()
pwd = String(Base64.decodeBase64('UHJhbWF0aUAxMjM='), 'UTF-8')
auth_response = authenticate_user_in_azure(AZURE_TENANT_ID, AZURE_USER_NAME, pwd, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
print "End Time: %s" % datetime.now()
print "Auth response: %s" % auth_response
azure_auth_response_json = json.loads(auth_response)
if 'upn' in azure_auth_response_json:
    name = azure_auth_response_json['upn']
    print "upn is present: %s" % name
elif 'error' in azure_auth_response_json:
    error = azure_auth_response_json['error']
    error_msg = azure_auth_response_json['error_description']
    print "Error is %s" % error
    print "Error Message is %s" % error_msg


# azureAuthConnector = AzureAuthConnector()
# response = azureAuthConnector.authenticateUserInAzure(AZURE_TENANT_ID, AZURE_USER_NAME, Util.decode("UHJhbWF0aUAxMjM="), AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
# print "Auth response: " + response

# accessToken = azureAuthConnector.acquireAccessTokenByClientCredentials(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
# print "access_token obtained by client credentials: " + accessToken
# userName = azureAuthConnector.getUserNameByIdFromGraph(AZURE_USER_ID, AZURE_TENANT_ID, accessToken)
# print "Azure username is: " + userName

