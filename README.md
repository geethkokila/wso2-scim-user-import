# wso2-scim-user-import
This repository can be used for importing users to a tenant to a secondary user store. 

This requires java 17 - 21 version to run and maven 3.9.9

Following configurations has to be there in config.properties file

    # ==== CSV paths ====
    users.csv.path=./db-dump/SampleData/um_user.csv
    roles.csv.path=./db-dump/SampleData/um_role.csv
    userAttributes.csv.path=/./db-dump/SampleData/um_user_attribute.csv
    userRoleMappings.csv.path=./db-dump/SampleData/um_user_role.csv
    
    # ==== Output files ====
    existingUsers.out.path=./db-dump/errors/existing-users.csv
    errorLog.out.path=./db-dump/errors/import-errors.csv
    
    # ==== WSO2 IS connection ====
    baseUrl=https://localhost:9443
    
    # Tenant domain 
    tenantDomain=test.com
    
    # SCIM credentials 
    scim.username=admin@test.com
    scim.password=123456
    
    # Target user store 
    userStore.domain=EUM
    
    # Debug logging (true/false)
    debug.enabled=true


