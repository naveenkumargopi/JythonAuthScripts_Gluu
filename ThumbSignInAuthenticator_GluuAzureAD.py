# Author: Naveen Kumar Gopi

from org.xdi.service.cdi.util import CdiUtil
from org.xdi.oxauth.security import Identity
from org.xdi.model.custom.script.type.auth import PersonAuthenticationType
from org.xdi.oxauth.service import AuthenticationService, UserService
from org.xdi.oxauth.model.common import User
from org.xdi.util import StringHelper, ArrayHelper
from org.xdi.oxauth.util import ServerUtil
from com.pramati.ts.thumbsignin_java_sdk import ThumbsigninApiController
from com.thumbsignin import AzureAuthConnector
from org.json import JSONObject
from org.xdi.oxauth.model.util import Base64Util
from java.lang import String
from java.util import Arrays, ArrayList, HashMap, IdentityHashMap

import java


class PersonAuthentication(PersonAuthenticationType):

    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "ThumbSignIn. Initialization"

        global ts_host
        ts_host = configurationAttributes.get("ts_host").getValue2()
        print "ThumbSignIn. Initialization. Value of ts_host is %s" % ts_host

        global ts_apiKey
        ts_apiKey = configurationAttributes.get("ts_apiKey").getValue2()
        print "ThumbSignIn. Initialization. Value of ts_apiKey is %s" % ts_apiKey

        global ts_apiSecret
        ts_apiSecret = configurationAttributes.get("ts_apiSecret").getValue2()

        global ts_statusPath
        ts_statusPath = "/ts/secure/txn-status/"

        global azure_tenant_id
        azure_tenant_id = configurationAttributes.get("azure_tenant_id").getValue2()
        print "ThumbSignIn. Initialization. Value of azure_tenant_id is %s" % azure_tenant_id

        global azure_client_id
        azure_client_id = configurationAttributes.get("azure_client_id").getValue2()
        print "ThumbSignIn. Initialization. Value of azure_client_id is %s" % azure_client_id

        global azure_client_secret
        azure_client_secret = configurationAttributes.get("azure_client_secret").getValue2()
        print "ThumbSignIn. Initialization. Value of azure_client_secret is %s" % azure_client_secret

        self.azureAuthConnector = AzureAuthConnector()

        if (configurationAttributes.containsKey("azuread_attributes_list") and
                configurationAttributes.containsKey("gluuldap_attributes_list")):

            azureadAttributesList = configurationAttributes.get("azuread_attributes_list").getValue2()
            if (StringHelper.isEmpty(azureadAttributesList)):
                print "ThumbSignIn: Initialization. The property azuread_attributes_list is empty"
                return False

            gluuldapAttributesList = configurationAttributes.get("gluuldap_attributes_list").getValue2()
            if (StringHelper.isEmpty(gluuldapAttributesList)):
                print "ThumbSignIn: Initialization. The property gluuldap_attributes_list is empty"
                return False

            self.attributesMapping = self.prepareAttributesMapping(azureadAttributesList, gluuldapAttributesList)
            if (self.attributesMapping == None):
                print "ThumbSignIn: Initialization. The attributes mapping isn't valid"
                return False

        print "ThumbSignIn. Initialized successfully"
        return True

    def prepareAttributesMapping(self, azureadAttributesList, gluuldapAttributesList):
        try:
            azureadAttributesListArray = StringHelper.split(azureadAttributesList, ",")
            if (ArrayHelper.isEmpty(azureadAttributesListArray)):
                print("ThumbSignIn: PrepareAttributesMapping. There is no attributes specified in azureadAttributesList property")
                return None

            gluuldapAttributesListArray = StringHelper.split(gluuldapAttributesList, ",")
            if (ArrayHelper.isEmpty(gluuldapAttributesListArray)):
                print("ThumbSignIn: PrepareAttributesMapping. There is no attributes specified in gluuldapAttributesList property")
                return None

            if (len(azureadAttributesListArray) != len(gluuldapAttributesListArray)):
                print("ThumbSignIn: PrepareAttributesMapping. The number of attributes in azureadAttributesList and gluuldapAttributesList isn't equal")
                return None

            attributeMapping = IdentityHashMap()
            i = 0
            count = len(azureadAttributesListArray)
            while (i < count):
                azureadAttribute = StringHelper.toLowerCase(azureadAttributesListArray[i])
                gluuldapAttribute = StringHelper.toLowerCase(gluuldapAttributesListArray[i])
                attributeMapping.put(azureadAttribute, gluuldapAttribute)
                i = i + 1

            return attributeMapping
        except Exception, err:
            print("ThumbSignIn: Exception inside prepareAttributesMapping " + str(err))

    def destroy(self, configurationAttributes):
        print "ThumbSignIn. Destroy"
        return True

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def setRelyingPartyLoginUrl(self, identity):
        print "ThumbSignIn. Inside setRelyingPartyLoginUrl..."
        sessionId =  identity.getSessionId()
        sessionAttribute = sessionId.getSessionAttributes()
        stateJWTToken = sessionAttribute.get("state")

        relyingPartyLoginUrl = ""
        relyingPartyId = ""
        if (stateJWTToken != None) :
            stateJWTTokenArray = String(stateJWTToken).split("\\.")
            stateJWTTokenPayload = stateJWTTokenArray[1]
            statePayloadStr = String(Base64Util.base64urldecode(stateJWTTokenPayload), "UTF-8")
            statePayloadJson = JSONObject(statePayloadStr)
            print "ThumbSignIn. Value of state JWT token Payload is %s" % statePayloadJson
            additional_claims = statePayloadJson.get("additional_claims")
            relyingPartyId = additional_claims.get("relyingPartyId")
            print "ThumbSignIn. Value of relyingPartyId is %s" % relyingPartyId
            identity.setWorkingParameter("relyingPartyId", relyingPartyId)

            if (String(relyingPartyId).startsWith("google.com")):
                #google.com/a/unphishableenterprise.com
                relyingPartyIdArray = String(relyingPartyId).split("/")
                googleDomain = relyingPartyIdArray[2]
                print "ThumbSignIn. Value of googleDomain is %s" % googleDomain
                relyingPartyLoginUrl = "https://www.google.com/accounts/AccountChooser?hd="+ googleDomain + "%26continue=https://apps.google.com/user/hub"
                #elif (String(relyingPartyId).startsWith("xyz")):
                #relyingPartyLoginUrl = "xyz.com"
            else:
                #If relyingPartyLoginUrl is empty, Gluu's default login URL will be used
                relyingPartyLoginUrl = ""

        print "ThumbSignIn. Value of relyingPartyLoginUrl is %s" % relyingPartyLoginUrl
        identity.setWorkingParameter("relyingPartyLoginUrl", relyingPartyLoginUrl)
        return None

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "ThumbSignIn. Inside prepareForStep. Step %d" % step
        identity = CdiUtil.bean(Identity)
        authenticationService = CdiUtil.bean(AuthenticationService)

        global ts_host
        global ts_apiKey
        global ts_apiSecret
        global ts_statusPath

        identity.setWorkingParameter("ts_host", ts_host)
        identity.setWorkingParameter("ts_statusPath", ts_statusPath)

        self.setRelyingPartyLoginUrl(identity)
        thumbsigninApiController = ThumbsigninApiController()

        if (step == 1 or step == 3):
            print "ThumbSignIn. Prepare for step 1"

            # Invoking the authenticate ThumbSignIn API via the Java SDK
            authenticateResponseJsonStr = thumbsigninApiController.handleThumbSigninRequest("authenticate", ts_apiKey, ts_apiSecret)
            print "ThumbSignIn. Value of authenticateResponseJsonStr is %s" % authenticateResponseJsonStr

            authenticateResponseJsonObj = JSONObject(authenticateResponseJsonStr)
            transactionId = authenticateResponseJsonObj.get("transactionId")
            authenticationStatusRequest = "authStatus/" + transactionId
            print "ThumbSignIn. Value of authenticationStatusRequest is %s" % authenticationStatusRequest

            authorizationHeaderJsonStr = thumbsigninApiController.getAuthorizationHeaderJsonStr(authenticationStatusRequest, ts_apiKey, ts_apiSecret)
            print "ThumbSignIn. Value of authorizationHeaderJsonStr is %s" % authorizationHeaderJsonStr
            # {"authHeader":"HmacSHA256 Credential=XXX, SignedHeaders=accept;content-type;x-ts-date, Signature=XXX","XTsDate":"XXX"}

            authorizationHeaderJsonObj = JSONObject(authorizationHeaderJsonStr)
            authorizationHeader = authorizationHeaderJsonObj.get("authHeader")
            xTsDate = authorizationHeaderJsonObj.get("XTsDate")
            print "ThumbSignIn. Value of authorizationHeader is %s" % authorizationHeader
            print "ThumbSignIn. Value of xTsDate is %s" % xTsDate

            identity.setWorkingParameter("authenticateResponseJsonStr", authenticateResponseJsonStr)
            identity.setWorkingParameter("authorizationHeader", authorizationHeader)
            identity.setWorkingParameter("xTsDate", xTsDate)

            return True

        elif (step == 2):
            print "ThumbSignIn. Prepare for step 2"

            if (identity.isSetWorkingParameter("userLoginFlow")):
                userLoginFlow = identity.getWorkingParameter("userLoginFlow")
                print "ThumbSignIn. Value of userLoginFlow is %s" % userLoginFlow

            user = authenticationService.getAuthenticatedUser()
            if (user == None):
                print "ThumbSignIn. Prepare for step 2. Failed to determine user name"
                return False

            user_name = user.getUserId()
            print "ThumbSignIn. Prepare for step 2. user_name: " + user_name
            if (user_name == None):
                return False

            registerRequestPath = "register/" + user_name

            # Invoking the register ThumbSignIn API via the Java SDK
            registerResponseJsonStr = thumbsigninApiController.handleThumbSigninRequest(registerRequestPath, ts_apiKey, ts_apiSecret)
            print "ThumbSignIn. Value of registerResponseJsonStr is %s" % registerResponseJsonStr

            registerResponseJsonObj = JSONObject(registerResponseJsonStr)
            transactionId = registerResponseJsonObj.get("transactionId")
            registrationStatusRequest = "regStatus/" + transactionId
            print "ThumbSignIn. Value of registrationStatusRequest is %s" % registrationStatusRequest

            authorizationHeaderJsonStr = thumbsigninApiController.getAuthorizationHeaderJsonStr(registrationStatusRequest, ts_apiKey, ts_apiSecret)
            print "ThumbSignIn. Value of authorizationHeaderJsonStr is %s" % authorizationHeaderJsonStr
            # {"authHeader":"HmacSHA256 Credential=XXX, SignedHeaders=accept;content-type;x-ts-date, Signature=XXX","XTsDate":"XXX"}

            authorizationHeaderJsonObj = JSONObject(authorizationHeaderJsonStr)
            authorizationHeader = authorizationHeaderJsonObj.get("authHeader")
            xTsDate = authorizationHeaderJsonObj.get("XTsDate")
            print "ThumbSignIn. Value of authorizationHeader is %s" % authorizationHeader
            print "ThumbSignIn. Value of xTsDate is %s" % xTsDate

            identity.setWorkingParameter("userId", user_name)
            identity.setWorkingParameter("registerResponseJsonStr", registerResponseJsonStr)
            identity.setWorkingParameter("authorizationHeader", authorizationHeader)
            identity.setWorkingParameter("xTsDate", xTsDate)

            return True
        else:
            return False

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "ThumbSignIn. Inside authenticate. Step %d" % step
        authenticationService = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)

        global ts_host
        global ts_apiKey
        global ts_apiSecret
        global ts_statusPath

        identity.setWorkingParameter("ts_host", ts_host)
        identity.setWorkingParameter("ts_statusPath", ts_statusPath)

        thumbsigninApiController = ThumbsigninApiController()

        if (step == 1 or step == 3):
            print "ThumbSignIn. Authenticate for Step %d" % step

            login_flow = ServerUtil.getFirstValue(requestParameters, "login_flow")
            print "ThumbSignIn. Value of login_flow parameter is %s" % login_flow

            # Logic for ThumbSignIn Authentication Flow (Either step 1 or step 3)
            if (login_flow == "ThumbSignIn_Authentication" or login_flow == "ThumbSignIn_RegistrationSucess"):
                identity.setWorkingParameter("userLoginFlow", login_flow)
                print "ThumbSignIn. Value of userLoginFlow is %s" % identity.getWorkingParameter("userLoginFlow")
                logged_in_status = authenticationService.authenticate(self.getUserIdFromThumbSignIn(requestParameters, thumbsigninApiController))
                print "ThumbSignIn. logged_in status : %r" % (logged_in_status)
                return logged_in_status

            # Logic for username/password login flow (step 1)
            print "ThumbSignIn. User credentials login flow"
            identity.setWorkingParameter("userLoginFlow", "ThumbSignIn_Registration")
            print "ThumbSignIn. Value of userLoginFlow is %s" % identity.getWorkingParameter("userLoginFlow")
            logged_in = self.authenticateUserInAzureAD(identity, authenticationService)
            print "ThumbSignIn. Status of User Credentials based Authentication : %r" % (logged_in)

            # When the username/password login fails, we need to reinitialize the ThumbSignIn data again before sending error response to UI
            if (not logged_in):
                self.initializeThumbSignInDataForWidget(thumbsigninApiController, identity)
                return False

            print "ThumbSignIn. Authenticate successful for step %d" % step
            return True

        elif (step == 2):
            print "ThumbSignIn. Registration flow (step 2)"
            self.verifyUserLoginFlow(identity)

            user = self.getAuthenticatedUserFromGluu(authenticationService)
            if user == None:
                print "ThumbSignIn. Registration flow (step 2). Failed to determine user name"
                return False

            user_name = user.getUserId()
            print "ThumbSignIn. Registration flow (step 2) successful. user_name: " + user_name
            return True

        else:
            return False

    def authenticateUserInAzureAD(self, identity, authenticationService):
        credentials = identity.getCredentials()
        user_name = credentials.getUsername()
        user_password = credentials.getPassword()
        print "ThumbSignIn. user_name: " + user_name
        logged_in = False
        if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):

            # Special condition to allow for Gluu admin login
            if (StringHelper.equals(user_name, "admin")):
                return self.authenticateUserInGluuLDAP(authenticationService, user_name, user_password)

            # Authenticate user credentials with Azure AD non-interactively
            azureAuthResponse = self.azureAuthConnector.authenticateUserInAzure(azure_tenant_id, user_name, user_password, azure_client_id, azure_client_secret)
            print "ThumbSignIn. Value of azureAuthResponse is %s" % azureAuthResponse
            azureAuthResponseJsonObj = JSONObject(azureAuthResponse)
            if (azureAuthResponseJsonObj.has("upn")):
                # Azure authentication has succeeded. User needs to be enrolled in Gluu LDAP
                user = self.enrollAzureUserInGluuLDAP(azureAuthResponseJsonObj)
                if (user == None):
                    # User Enrollment in Gluu LDAP has failed
                    logged_in = False
                else:
                    # Authenticating the user within Gluu
                    userAuthenticatedInGluu = authenticationService.authenticate(user.getUserId())
                    print "ThumbSignIn: Authentication status of the user enrolled in Gluu LDAP %r " % (userAuthenticatedInGluu)
                    return userAuthenticatedInGluu
            else:
                # Azure authentication has failed.
                logged_in = False
        return logged_in

    def enrollAzureUserInGluuLDAP(self, azureAuthResponseJsonObj):
        # azuread_attributes_list  =  upn,given_name,family_name,upn
        # gluuldap_attributes_list =  uid,givenName,sn,mail
        # attributesMapping = ["upn:uid", "given_name:givenName", "family_name:sn", "upn:mail"]
        userService = CdiUtil.bean(UserService)
        azureUserPrincipalName = azureAuthResponseJsonObj.get("upn")
        foundUser = self.findUserFromGluuLDAPByAttribute(userService, "mail", azureUserPrincipalName)
        print "ThumbSignIn. Value of foundUser is %s" % foundUser
        if (foundUser == None):
            newUser = User()
            self.populateUserObjWithAzureUserData(newUser, azureAuthResponseJsonObj)
            try:
                # Add azure user in Gluu LDAP
                foundUser = userService.addUser(newUser, True)
                foundUserId = foundUser.getUserId()
                print("ThumbSignIn: Azure User added successfully in Gluu LDAP " + foundUserId)
            except Exception, err:
                print("ThumbSignIn: Error in adding azure user to Gluu LDAP:" + str(err))
                return None
        else:
            self.populateUserObjWithAzureUserData(foundUser, azureAuthResponseJsonObj)
            try:
                # Update the user in Gluu LDAP with latest values from Azure AD
                foundUser = userService.updateUser(foundUser)
                foundUserId = foundUser.getUserId()
                print("ThumbSignIn: Azure User updated successfully in Gluu LDAP " + foundUserId)
            except Exception, err:
                print("ThumbSignIn: Error in updating azure user to Gluu LDAP:" + str(err))
                return None

        return foundUser

    def authenticateUserInGluuLDAP(self, authenticationService, user_name, user_password):
        return authenticationService.authenticate(user_name, user_password)

    def getAuthenticatedUserFromGluu(self, authenticationService):
        return authenticationService.getAuthenticatedUser()

    def findUserFromGluuLDAPByAttribute(self, userService, attributeName, attributeValue):
        return userService.getUserByAttribute(attributeName, attributeValue)

    def populateUserObjWithAzureUserData(self, user, azureAuthResponseJsonObj):
        for attributesMappingEntry in self.attributesMapping.entrySet():
            azureadAttribute = attributesMappingEntry.getKey()                              #upn
            gluuldapAttribute = attributesMappingEntry.getValue()                           #uid
            gluuldapAttributeValue = azureAuthResponseJsonObj.get(azureadAttribute)         #demo@ak1976hotmail.onmicrosoft.com
            print "Value of gluuldapAttribute %s" % gluuldapAttribute
            print "Value of gluuldapAttributeValue %s" % gluuldapAttributeValue
            if ((gluuldapAttribute != None) & (gluuldapAttributeValue != "undefined")):
                print gluuldapAttribute + gluuldapAttributeValue
                user.setAttribute(gluuldapAttribute, gluuldapAttributeValue)
        return None

    def initializeThumbSignInDataForWidget(self, thumbsigninApiController, identity):
        # Invoking the authenticate ThumbSignIn API via the Java SDK
        authenticateResponseJsonStr = thumbsigninApiController.handleThumbSigninRequest("authenticate", ts_apiKey, ts_apiSecret)
        print "ThumbSignIn. Value of authenticateResponseJsonStr is %s" % authenticateResponseJsonStr

        authenticateResponseJsonObj = JSONObject(authenticateResponseJsonStr)
        transactionId = authenticateResponseJsonObj.get("transactionId")
        authenticationStatusRequest = "authStatus/" + transactionId
        print "ThumbSignIn. Value of authenticationStatusRequest is %s" % authenticationStatusRequest

        authorizationHeaderJsonStr = thumbsigninApiController.getAuthorizationHeaderJsonStr(authenticationStatusRequest, ts_apiKey, ts_apiSecret)
        print "ThumbSignIn. Value of authorizationHeaderJsonStr is %s" % authorizationHeaderJsonStr
        # {"authHeader":"HmacSHA256 Credential=XXX, SignedHeaders=accept;content-type;x-ts-date, Signature=XXX","XTsDate":"XXX"}

        authorizationHeaderJsonObj = JSONObject(authorizationHeaderJsonStr)
        authorizationHeader = authorizationHeaderJsonObj.get("authHeader")
        xTsDate = authorizationHeaderJsonObj.get("XTsDate")
        print "ThumbSignIn. Value of authorizationHeader is %s" % authorizationHeader
        print "ThumbSignIn. Value of xTsDate is %s" % xTsDate

        identity.setWorkingParameter("authenticateResponseJsonStr", authenticateResponseJsonStr)
        identity.setWorkingParameter("authorizationHeader", authorizationHeader)
        identity.setWorkingParameter("xTsDate", xTsDate)
        return None

    def getUserIdFromThumbSignIn(self, requestParameters, thumbsigninApiController):
        transactionId = ServerUtil.getFirstValue(requestParameters, "transactionId")
        print "ThumbSignIn. Value of transactionId is %s" % transactionId
        getUserRequest = "getUser/" + transactionId
        print "ThumbSignIn. Value of getUserRequest is %s" % getUserRequest

        getUserResponseJsonStr = thumbsigninApiController.handleThumbSigninRequest(getUserRequest, ts_apiKey, ts_apiSecret)
        print "ThumbSignIn. Value of getUserResponseJsonStr is %s" % getUserResponseJsonStr
        getUserResponseJsonObj = JSONObject(getUserResponseJsonStr)
        thumbSignIn_UserId = getUserResponseJsonObj.get("userId")
        print "ThumbSignIn. Value of thumbSignIn_UserId is %s" % thumbSignIn_UserId
        return thumbSignIn_UserId

    def verifyUserLoginFlow(self, identity):
        if (identity.isSetWorkingParameter("userLoginFlow")):
            userLoginFlow = identity.getWorkingParameter("userLoginFlow")
            print "ThumbSignIn. Value of userLoginFlow is %s" % userLoginFlow
        else:
            identity.setWorkingParameter("userLoginFlow", "ThumbSignIn_Registration")
            print "ThumbSignIn. Setting the value of userLoginFlow to %s" % identity.getWorkingParameter("userLoginFlow")

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        print "ThumbSignIn. Inside getCountAuthenticationSteps.."
        identity = CdiUtil.bean(Identity)

        userLoginFlow = identity.getWorkingParameter("userLoginFlow")
        print "ThumbSignIn. Value of userLoginFlow is %s" % userLoginFlow
        if (userLoginFlow == "ThumbSignIn_Authentication"):
            print "ThumbSignIn. Total Authentication Steps is: 1"
            return 1
            #If the userLoginFlow is registration, then we can handle the ThumbSignIn registration as part of the second step
        print "ThumbSignIn. Total Authentication Steps is: 3"
        return 3

    def getPageForStep(self, configurationAttributes, step):
        print "ThumbSignIn. Inside getPageForStep. Step %d" % step
        if (step == 2):
            return "/auth/thumbsignin/tsRegister.xhtml"
        elif (step == 3):
            return "/auth/thumbsignin/tsRegistrationSuccess.xhtml"
        else:
            return "/auth/thumbsignin/tsLogin.xhtml"

    def logout(self, configurationAttributes, requestParameters):
        return True