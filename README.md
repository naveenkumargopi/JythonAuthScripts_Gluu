
## Configurations required for ThumbSignInAuthenticator_GluuLocalLDAP.py:

### A) Required Custom property (to be configured in Gluu Admin Dashboard):

    1) `ts_host = https://api.thumbsignin.com`
    
    2) `ts_apiKey` 
    
    3) `ts_apiSecret` 
    
    Note:
    
    a) We need to create an account for the Gluu server instance in ThumbSignIn ([https://thumbsignin.com]) and
       configure the application id and secret in the `ts_apiKey` and `ts_apiSecret` respectively
       
    b) To login into gluu dashboard as administrator, goto Gluu URL (for eg., [https://idp-stage.thumbsignin.com])
       and login with admin credentials

### B) Required Dependencies:

    1) ThumbSignIn Java SDK can be downloaded from [https://thumbsignin.com/download/thumbsigninJavaSdk] and 
       needs to be deployed in `'/opt/gluu-server-3.1.2/opt/gluu/jetty/oxauth/lib/ext'` folder of Gluu Server
       
    2) ThumbSignIn UI components can be deployed in Gluu Server via below steps:
    
        a) Clone the project from [https://gitlab.pramati.com/ThumbSignIn/oxauth]. This project contains all the 
           required TSI specific UI changes under `'/oxauth/auth/thumbsignin'` folder of this project.
           
        b) cd into `oxauth` folder
        
        c) To archive all the contents into a .war file : `jar -cvf oxauth.war *`
        
        d) Deploy this oxauth.war file in the `'/opt/gluu-server-3.1.2/opt/gluu/jetty/oxauth/webapps'` folder of
           Gluu server
           
    3) Restart the oxauth module of Gluu Server for the UI and SDK changes to take effect.
    
       Login into gluu server from terminal and run below commands:
       
       `sudo service gluu-server-3.1.2 login`
       
       `service oxauth stop`
       
       `service oxauth start` 
      
### C) Enabling the script in Gluu Admin Dashboard:

   a) Login into Gluu Admin Dashboard -> Go to `"Manage Authentication"` -> `"Default Authentication Method"` ->
      Select `'thumbsignin'` as the default acr and update the configuration.
      
      Note: It is also recommended to set the UnAuthenticated Session Timeout Parameter to 240 secs
      
      Login as Gluu Admin -> JSON Configuration -> oxAuth Configuration and update `'sessionIdUnauthenticatedUnusedLifetime'` parameter to 240 secs.
      
   b) To test the login flow in Gluu, we can add new users in Gluu LDAP as shown below. 
   
      Login as Gluu Admin -> Click `'Users'` ->  Click `'Add Person'`
      
Note: It is recommended to test the new login flow in a different browser to avoid admin account lockout in Gluu.

For more information, we can also refer to [https://thumbsignin.com/download/thumbsigninGluuIntegrationDoc]
   
## Configurations required for ThumbSignInAuthenticator_GluuAzureAD.py:

### A) Required Custom property (to be configured in Gluu Admin Dashboard):

    1) `ts_host = https://api.thumbsignin.com`
    
    2) `ts_apiKey`
    
    3) `ts_apiSecret`
    
    4) `azure_tenant_id`
    
    5) `azure_client_id`
    
    6) `azure_client_secret`
    
    7) `azure_ad_attributes_list = oid`
    
    8) `gluu_ldap_attributes_list = uid`
    
    Note:
    
    a) An administrator of the Azure AD portal ([portal.azure.com]) needs to create an application for Gluu Server in the azure portal (with necessary permissions)
       and configure the tenant id, client id and client secret in the Custom properties of this Jython script.
       
       To connect to our internal Azure AD test instance, we can use the below values:
       
       `azure_tenant_id = c5bd07ef-f708-4577-84ce-e0e1faca9b8f`
       
       `azure_client_id = 30408b60-ccdc-4533-852a-220e75a6633f`
       
       `azure_client_secret = WNbKiL0xj8PJkAk+LkdtQuUfhYjCNUFFJ94d1H2vHqw=`
       
    b) If we need to sync the name and email id of the users from Azure AD into Gluu LDAP (in addition to the UUID),
       then we can configure the below 2 parameters as follows.
       
       `azure_ad_attributes_list = oid,given_name,family_name,upn`
       
       `gluu_ldap_attributes_list = uid,givenName,sn,mail`

### B) Required Dependencies:

    1) ThumbSignIn Java SDK can be downloaded from [https://thumbsignin.com/download/thumbsigninJavaSdk] and 
       needs to be deployed in `'/opt/gluu-server-3.1.2/opt/gluu/jetty/oxauth/lib/ext'` folder of Gluu Server
       
    2) We also need to deploy the Azure Java SDK in Gluu Server. Steps are given below:
    
       a) Clone the project from [https://gitlab.pramati.com/ThumbSignIn/azurejavasdkforgluu]
       
       b) cd into the project folder
       
       c) Run the command: `./gradlew fatJar`
       
       d) The above command will generate the FAT jar `'AzureJavaSDKForGluu-all.jar'` in the `'build/libs'` folder
       
       e) Deploy this FAT jar in the `'/opt/gluu-server-3.1.2/opt/gluu/jetty/oxauth/lib/ext'` folder of Gluu Server.
       
    3) ThumbSignIn UI components can be deployed in Gluu Server via below steps:
    
        a) Clone the project from [https://gitlab.pramati.com/ThumbSignIn/oxauth]. This project contains all the 
           required TSI specific UI changes under `'/oxauth/auth/thumbsignin'` folder of this project.
           
        b) cd into `oxauth` folder
        
        c) To archive all the contents into a .war file : `jar -cvf oxauth.war *`
        
        d) Deploy this oxauth.war file in the `'/opt/gluu-server-3.1.2/opt/gluu/jetty/oxauth/webapps'` folder of
           Gluu server
           
    4) Restart the oxauth module of Gluu Server for the UI and SDK changes to take effect.
    
       Login into gluu server from terminal and run below commands:
       
       `sudo service gluu-server-3.1.2 login`
       
       `service oxauth stop`
       
       `service oxauth start` 
      
### C) Enabling the script in Gluu Admin Dashboard:

   a) Login into Gluu Admin Dashboard -> Go to `"Manage Authentication"` -> `"Default Authentication Method"` ->
      Select `'thumbsignin_withazuread'` as the default acr and update the configuration.
      
   Note: It is also recommended to set the UnAuthenticated Session Timeout Parameter to 240 secs
   
   Login as Gluu Admin -> JSON Configuration -> oxAuth Configuration and update `'sessionIdUnauthenticatedUnusedLifetime'` parameter to 240 secs.
   
   b) To test the login flow in Gluu, we can add new users in Azure AD as shown below. 
   
      i) Login into Azure portal ([portal.azure.com]) with admin credentials.
      
      ii) Then click `'Azure Active Directory'` -> `Manage Users` -> Click `'New user'` button
      
      iii) The portal will provide a default password for this new user(this will be expired by default). 
      
      iv) We need to login once with the new user credentials in portal.azure.com and we will be prompted to change the expired password.
      
Note: It is recommended to test the new login flow in a different browser to avoid admin account lockout in Gluu.
