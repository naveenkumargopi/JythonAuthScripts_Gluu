from com.thumbsignin import AzureAuthConnector
from com.thumbsignin.util import Util

azureAuthConnector = AzureAuthConnector()

AZURE_TENANT_ID = "c5bd07ef-f708-4577-84ce-e0e1faca9b8f"
AZURE_CLIENT_ID = "30408b60-ccdc-4533-852a-220e75a6633f"
AZURE_CLIENT_SECRET = "WNbKiL0xj8PJkAk+LkdtQuUfhYjCNUFFJ94d1H2vHqw="
AZURE_USER_NAME = "demo@ak1976hotmail.onmicrosoft.com"
AZURE_USER_ID = "57d47a0b-b834-4906-b60b-2bd177f6369e"

response = azureAuthConnector.authenticateUserInAzure(AZURE_TENANT_ID, AZURE_USER_NAME, Util.decode("UHJhbWF0aUAxMjM="), AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
print "Auth response: " + response

accessToken = azureAuthConnector.acquireAccessTokenByClientCredentials(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
print "access_token obtained by client credentials: " + accessToken
userName = azureAuthConnector.getUserNameByIdFromGraph(AZURE_USER_ID, AZURE_TENANT_ID, accessToken)
print "Azure username is: " + userName

