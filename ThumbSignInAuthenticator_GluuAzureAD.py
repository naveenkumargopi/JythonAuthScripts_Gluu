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
from java.util import IdentityHashMap

import java


class PersonAuthentication(PersonAuthenticationType):

    def __init__(self, current_time_millis):
        self.currentTimeMillis = current_time_millis
        self.thumbsigninApiController = ThumbsigninApiController()
        self.azureAuthConnector = AzureAuthConnector()

    def init(self, configuration_attributes):
        print "ThumbSignIn. Initialization"

        global ts_host
        ts_host = configuration_attributes.get("ts_host").getValue2()
        print "ThumbSignIn. Initialization. Value of ts_host is %s" % ts_host

        global ts_api_key
        ts_api_key = configuration_attributes.get("ts_apiKey").getValue2()
        print "ThumbSignIn. Initialization. Value of ts_api_key is %s" % ts_api_key

        global ts_api_secret
        ts_api_secret = configuration_attributes.get("ts_apiSecret").getValue2()

        global ts_statusPath
        ts_statusPath = "/ts/secure/txn-status/"

        global AUTHENTICATE
        AUTHENTICATE = "authenticate"

        global REGISTER
        REGISTER = "register"

        global TRANSACTION_ID
        TRANSACTION_ID = "transactionId"

        global USER_ID
        USER_ID = "userId"

        global USER_LOGIN_FLOW
        USER_LOGIN_FLOW = "userLoginFlow"

        global THUMBSIGNIN_AUTHENTICATION
        THUMBSIGNIN_AUTHENTICATION = "ThumbSignIn_Authentication"

        global THUMBSIGNIN_REGISTRATION
        THUMBSIGNIN_REGISTRATION = "ThumbSignIn_Registration"

        global THUMBSIGNIN_LOGIN_POST_REGISTRATION
        THUMBSIGNIN_LOGIN_POST_REGISTRATION = "ThumbSignIn_RegistrationSucess"

        global RELYING_PARTY_ID
        RELYING_PARTY_ID = "relyingPartyId"

        global RELYING_PARTY_LOGIN_URL
        RELYING_PARTY_LOGIN_URL = "relyingPartyLoginUrl"

        global TSI_LOGIN_PAGE
        TSI_LOGIN_PAGE = "/auth/thumbsignin/tsLogin.xhtml"

        global TSI_REGISTER_PAGE
        TSI_REGISTER_PAGE = "/auth/thumbsignin/tsRegister.xhtml"

        global TSI_LOGIN_POST_REGISTRATION_PAGE
        TSI_LOGIN_POST_REGISTRATION_PAGE = "/auth/thumbsignin/tsRegistrationSuccess.xhtml"

        global azure_tenant_id
        azure_tenant_id = configuration_attributes.get("azure_tenant_id").getValue2()
        print "ThumbSignIn. Initialization. Value of azure_tenant_id is %s" % azure_tenant_id

        global azure_client_id
        azure_client_id = configuration_attributes.get("azure_client_id").getValue2()
        print "ThumbSignIn. Initialization. Value of azure_client_id is %s" % azure_client_id

        global azure_client_secret
        azure_client_secret = configuration_attributes.get("azure_client_secret").getValue2()

        global attributes_mapping

        if (configuration_attributes.containsKey("azure_ad_attributes_list") and
                configuration_attributes.containsKey("gluu_ldap_attributes_list")):

            azure_ad_attributes_list = configuration_attributes.get("azure_ad_attributes_list").getValue2()
            if StringHelper.isEmpty(azure_ad_attributes_list):
                print "ThumbSignIn: Initialization. The property azure_ad_attributes_list is empty"
                return False

            gluu_ldap_attributes_list = configuration_attributes.get("gluu_ldap_attributes_list").getValue2()
            if StringHelper.isEmpty(gluu_ldap_attributes_list):
                print "ThumbSignIn: Initialization. The property gluu_ldap_attributes_list is empty"
                return False

            attributes_mapping = self.attribute_mapping_function(azure_ad_attributes_list, gluu_ldap_attributes_list)
            if attributes_mapping is None:
                print "ThumbSignIn: Initialization. The attributes mapping isn't valid"
                return False

        print "ThumbSignIn. Initialized successfully"
        return True

    @staticmethod
    def attribute_mapping_function(azure_ad_attributes_list, gluu_ldap_attributes_list):
        try:
            azure_ad_attributes_list_array = StringHelper.split(azure_ad_attributes_list, ",")
            if ArrayHelper.isEmpty(azure_ad_attributes_list_array):
                print("ThumbSignIn: There is no attributes specified in azure_ad_attributes_list property")
                return None

            gluu_ldap_attributes_list_array = StringHelper.split(gluu_ldap_attributes_list, ",")
            if ArrayHelper.isEmpty(gluu_ldap_attributes_list_array):
                print("ThumbSignIn: There is no attributes specified in gluu_ldap_attributes_list property")
                return None

            if len(azure_ad_attributes_list_array) != len(gluu_ldap_attributes_list_array):
                print("ThumbSignIn: The number of attributes isn't equal")
                return None

            attributes_map = IdentityHashMap()
            i = 0
            count = len(azure_ad_attributes_list_array)
            while i < count:
                azure_ad_attribute = StringHelper.toLowerCase(azure_ad_attributes_list_array[i])
                gluu_ldap_attribute = StringHelper.toLowerCase(gluu_ldap_attributes_list_array[i])
                attributes_map.put(azure_ad_attribute, gluu_ldap_attribute)
                i = i + 1

            return attributes_map
        except Exception, err:
            print("ThumbSignIn: Exception inside prepareAttributesMapping " + str(err))

    @staticmethod
    def set_relying_party_login_url(identity):
        print "ThumbSignIn. Inside set_relying_party_login_url..."
        session_id =  identity.getSessionId()
        session_attribute = session_id.getSessionAttributes()
        state_jwt_token = session_attribute.get("state")

        relying_party_login_url = ""
        if state_jwt_token is not None:
            state_jwt_token_array = String(state_jwt_token).split("\\.")
            state_jwt_token_payload = state_jwt_token_array[1]
            state_payload_str = String(Base64Util.base64urldecode(state_jwt_token_payload), "UTF-8")
            state_payload_json = JSONObject(state_payload_str)
            print "ThumbSignIn. Value of state JWT token Payload is %s" % state_payload_json
            additional_claims = state_payload_json.get("additional_claims")
            relying_party_id = additional_claims.get(RELYING_PARTY_ID)
            print "ThumbSignIn. Value of relying_party_id is %s" % relying_party_id
            identity.setWorkingParameter(RELYING_PARTY_ID, relying_party_id)

            if String(relying_party_id).startsWith("google.com"):
                # google.com/a/unphishableenterprise.com
                relying_party_id_array = String(relying_party_id).split("/")
                google_domain = relying_party_id_array[2]
                print "ThumbSignIn. Value of google_domain is %s" % google_domain
                relying_party_login_url = "https://www.google.com/accounts/AccountChooser?hd="+ google_domain + "%26continue=https://apps.google.com/user/hub"
                # elif (String(relying_party_id).startsWith("xyz")):
                # relying_party_login_url = "xyz.com"
            else:
                # If relying_party_login_url is empty, Gluu's default login URL will be used
                relying_party_login_url = ""

        print "ThumbSignIn. Value of relying_party_login_url is %s" % relying_party_login_url
        identity.setWorkingParameter(RELYING_PARTY_LOGIN_URL, relying_party_login_url)
        return None

    def initialize_thumbsignin(self, identity, request_path):
        # Invoking the authenticate/register ThumbSignIn API via the Java SDK
        thumbsignin_response = self.thumbsigninApiController.handleThumbSigninRequest(request_path, ts_api_key, ts_api_secret)
        print "ThumbSignIn. Value of thumbsignin_response is %s" % thumbsignin_response

        thumbsignin_response_json = JSONObject(thumbsignin_response)
        transaction_id = thumbsignin_response_json.get(TRANSACTION_ID)
        status_request_type = "authStatus" if request_path == AUTHENTICATE else "regStatus"
        status_request = status_request_type + "/" + transaction_id
        print "ThumbSignIn. Value of status_request is %s" % status_request

        authorization_header = self.thumbsigninApiController.getAuthorizationHeaderJsonStr(status_request, ts_api_key, ts_api_secret)
        print "ThumbSignIn. Value of authorization_header is %s" % authorization_header
        # {"authHeader":"HmacSHA256 Credential=X,SignedHeaders=accept;content-type;x-ts-date,Signature=X","XTsDate":"X"}
        authorization_header_json = JSONObject(authorization_header)
        auth_header = authorization_header_json.get("authHeader")
        x_ts_date = authorization_header_json.get("XTsDate")

        tsi_response_key = "authenticateResponseJsonStr" if request_path == AUTHENTICATE else "registerResponseJsonStr"
        identity.setWorkingParameter(tsi_response_key, thumbsignin_response)
        identity.setWorkingParameter("authorizationHeader", auth_header)
        identity.setWorkingParameter("xTsDate", x_ts_date)
        return None

    def prepareForStep(self, configuration_attributes, request_parameters, step):
        print "ThumbSignIn. Inside prepareForStep. Step %d" % step
        identity = CdiUtil.bean(Identity)
        authentication_service = CdiUtil.bean(AuthenticationService)

        identity.setWorkingParameter("ts_host", ts_host)
        identity.setWorkingParameter("ts_statusPath", ts_statusPath)

        self.set_relying_party_login_url(identity)

        if step == 1 or step == 3:
            print "ThumbSignIn. Prepare for step 1"
            self.initialize_thumbsignin(identity, AUTHENTICATE)
            return True

        elif step == 2:
            print "ThumbSignIn. Prepare for step 2"
            if identity.isSetWorkingParameter(USER_LOGIN_FLOW):
                user_login_flow = identity.getWorkingParameter(USER_LOGIN_FLOW)
                print "ThumbSignIn. Value of user_login_flow is %s" % user_login_flow
            user = authentication_service.getAuthenticatedUser()
            if user is None:
                print "ThumbSignIn. Prepare for step 2. Failed to determine user name"
                return False
            user_name = user.getUserId()
            print "ThumbSignIn. Prepare for step 2. user_name: " + user_name
            if user_name is None:
                return False
            identity.setWorkingParameter(USER_ID, user_name)
            self.initialize_thumbsignin(identity, REGISTER + "/" + user_name)
            return True
        else:
            return False

    def get_user_id_from_thumbsignin(self, request_parameters):
        transaction_id = ServerUtil.getFirstValue(request_parameters, TRANSACTION_ID)
        print "ThumbSignIn. Value of transaction_id is %s" % transaction_id
        get_user_request = "getUser/" + transaction_id
        print "ThumbSignIn. Value of get_user_request is %s" % get_user_request

        get_user_response = self.thumbsigninApiController.handleThumbSigninRequest(get_user_request, ts_api_key, ts_api_secret)
        print "ThumbSignIn. Value of get_user_response is %s" % get_user_response
        get_user_response_json = JSONObject(get_user_response)
        thumbsignin_user_id = get_user_response_json.get(USER_ID)
        print "ThumbSignIn. Value of thumbsignin_user_id is %s" % thumbsignin_user_id
        return thumbsignin_user_id

    def authenticate(self, configuration_attributes, request_parameters, step):
        print "ThumbSignIn. Inside authenticate. Step %d" % step
        authentication_service = CdiUtil.bean(AuthenticationService)
        identity = CdiUtil.bean(Identity)

        identity.setWorkingParameter("ts_host", ts_host)
        identity.setWorkingParameter("ts_statusPath", ts_statusPath)

        if step == 1 or step == 3:
            print "ThumbSignIn. Authenticate for Step %d" % step

            login_flow = ServerUtil.getFirstValue(request_parameters, "login_flow")
            print "ThumbSignIn. Value of login_flow parameter is %s" % login_flow

            # Logic for ThumbSignIn Authentication Flow (Either step 1 or step 3)
            if login_flow == THUMBSIGNIN_AUTHENTICATION or login_flow == THUMBSIGNIN_LOGIN_POST_REGISTRATION:
                identity.setWorkingParameter(USER_LOGIN_FLOW, login_flow)
                print "ThumbSignIn. Value of userLoginFlow is %s" % identity.getWorkingParameter(USER_LOGIN_FLOW)
                logged_in_status = authentication_service.authenticate(self.get_user_id_from_thumbsignin(request_parameters))
                print "ThumbSignIn. logged_in status : %r" % logged_in_status
                return logged_in_status

            # Logic for traditional login flow (step 1)
            print "ThumbSignIn. User credentials login flow"
            identity.setWorkingParameter(USER_LOGIN_FLOW, THUMBSIGNIN_REGISTRATION)
            print "ThumbSignIn. Value of userLoginFlow is %s" % identity.getWorkingParameter(USER_LOGIN_FLOW)
            logged_in = self.authenticate_user_in_azure_ad(identity, authentication_service)
            print "ThumbSignIn. Status of User Credentials based Authentication : %r" % logged_in

            # When the traditional login fails, reinitialize the ThumbSignIn data before sending error response to UI
            if not logged_in:
                self.initialize_thumbsignin(identity, AUTHENTICATE)
                return False

            print "ThumbSignIn. Authenticate successful for step %d" % step
            return True

        elif step == 2:
            print "ThumbSignIn. Registration flow (step 2)"
            self.verify_user_login_flow(identity)

            user = self.get_authenticated_user_from_gluu(authentication_service)
            if user is None:
                print "ThumbSignIn. Registration flow (step 2). Failed to determine user name"
                return False

            user_name = user.getUserId()
            print "ThumbSignIn. Registration flow (step 2) successful. user_name: %s" % user_name
            return True

        else:
            return False

    def authenticate_user_in_azure_ad(self, identity, authentication_service):
        credentials = identity.getCredentials()
        user_name = credentials.getUsername()
        user_password = credentials.getPassword()
        print "ThumbSignIn. user_name: %s" % user_name
        logged_in = False
        if StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password):

            # Special condition to allow for Gluu admin login
            if StringHelper.equals(user_name, "admin"):
                return self.authenticate_user_in_gluu_ldap(authentication_service, user_name, user_password)

            # Authenticate user credentials with Azure AD non-interactively
            azure_auth_response = self.azureAuthConnector.authenticateUserInAzure(azure_tenant_id, user_name, user_password, azure_client_id, azure_client_secret)
            print "ThumbSignIn. Value of azure_auth_response is %s" % azure_auth_response
            azure_auth_response_json = JSONObject(azure_auth_response)
            if azure_auth_response_json.has("upn"):
                # Azure authentication has succeeded. User needs to be enrolled in Gluu LDAP
                user = self.enroll_azure_user_in_gluu_ldap(azure_auth_response_json)
                if user is None:
                    # User Enrollment in Gluu LDAP has failed
                    logged_in = False
                else:
                    # Authenticating the user within Gluu
                    user_authenticated_in_gluu = authentication_service.authenticate(user.getUserId())
                    print "ThumbSignIn: Authentication status of the user enrolled in Gluu LDAP %r " % user_authenticated_in_gluu
                    return user_authenticated_in_gluu
            else:
                # Azure authentication has failed.
                logged_in = False
        return logged_in

    def enroll_azure_user_in_gluu_ldap(self, azure_auth_response_json):
        user_service = CdiUtil.bean(UserService)
        azure_user_principal_name = azure_auth_response_json.get("upn")
        found_user = self.find_user_from_gluu_ldap_by_attribute(user_service, "mail", azure_user_principal_name)
        print "ThumbSignIn. Value of found_user is %s" % found_user
        if found_user is None:
            new_user = User()
            self.populate_user_obj_with_azure_user_data(new_user, azure_auth_response_json)
            try:
                # Add azure user in Gluu LDAP
                found_user = user_service.addUser(new_user, True)
                found_user_id = found_user.getUserId()
                print("ThumbSignIn: Azure User added successfully in Gluu LDAP " + found_user_id)
            except Exception, err:
                print("ThumbSignIn: Error in adding azure user to Gluu LDAP:" + str(err))
                return None
        else:
            self.populate_user_obj_with_azure_user_data(found_user, azure_auth_response_json)
            try:
                # Update the user in Gluu LDAP with latest values from Azure AD
                found_user = user_service.updateUser(found_user)
                found_user_id = found_user.getUserId()
                print("ThumbSignIn: Azure User updated successfully in Gluu LDAP " + found_user_id)
            except Exception, err:
                print("ThumbSignIn: Error in updating azure user to Gluu LDAP:" + str(err))
                return None

        return found_user

    @staticmethod
    def authenticate_user_in_gluu_ldap(authentication_service, user_name, user_password):
        return authentication_service.authenticate(user_name, user_password)

    @staticmethod
    def get_authenticated_user_from_gluu(authentication_service):
        return authentication_service.getAuthenticatedUser()

    @staticmethod
    def find_user_from_gluu_ldap_by_attribute(user_service, attribute_name, attribute_value):
        return user_service.getUserByAttribute(attribute_name, attribute_value)

    @staticmethod
    def populate_user_obj_with_azure_user_data(user, azure_auth_response_json):
        # attributes_mapping = ["upn:uid", "given_name:givenName", "family_name:sn", "upn:mail"]
        for attributesMappingEntry in attributes_mapping.entrySet():
            azure_ad_attribute = attributesMappingEntry.getKey()
            gluu_ldap_attribute = attributesMappingEntry.getValue()
            gluu_ldap_attribute_value = azure_auth_response_json.get(azure_ad_attribute)
            if (gluu_ldap_attribute is not None) & (gluu_ldap_attribute_value != "undefined"):
                user.setAttribute(gluu_ldap_attribute, gluu_ldap_attribute_value)
        return None

    @staticmethod
    def verify_user_login_flow(identity):
        if identity.isSetWorkingParameter(USER_LOGIN_FLOW):
            user_login_flow = identity.getWorkingParameter(USER_LOGIN_FLOW)
            print "ThumbSignIn. Value of user_login_flow is %s" % user_login_flow
        else:
            identity.setWorkingParameter(USER_LOGIN_FLOW, THUMBSIGNIN_REGISTRATION)
            print "ThumbSignIn. Setting the value of user_login_flow to %s" % identity.getWorkingParameter(USER_LOGIN_FLOW)

    def getExtraParametersForStep(self, configuration_attributes, step):
        return None

    def getCountAuthenticationSteps(self, configuration_attributes):
        print "ThumbSignIn. Inside getCountAuthenticationSteps.."
        identity = CdiUtil.bean(Identity)

        user_login_flow = identity.getWorkingParameter(USER_LOGIN_FLOW)
        print "ThumbSignIn. Value of user_login_flow is %s" % user_login_flow
        if user_login_flow == THUMBSIGNIN_AUTHENTICATION:
            print "ThumbSignIn. Total Authentication Steps is: 1"
            return 1
        print "ThumbSignIn. Total Authentication Steps is: 3"
        return 3

    def getPageForStep(self, configuration_attributes, step):
        print "ThumbSignIn. Inside getPageForStep. Step %d" % step
        if step == 3:
            return TSI_LOGIN_POST_REGISTRATION_PAGE
        thumbsignin_page = TSI_REGISTER_PAGE if step == 2 else TSI_LOGIN_PAGE
        return thumbsignin_page

    def destroy(self, configuration_attributes):
        print "ThumbSignIn. Destroy"
        return True

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usage_type, configuration_attributes):
        return True

    def getAlternativeAuthenticationMethod(self, usage_type, configuration_attributes):
        return None

    def logout(self, configuration_attributes, request_parameters):
        return True
