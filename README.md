# wso2-scim-user-import
This repository can be used for importing users to a tenant to a secondary user store. 

This requires java 17 - 21 version to run and maven 3.9.9

Following configurations has to be there in config.properties file

# ==== CSV paths ====
users.csv.path=./db-dump/SampleData/um_user.csv
roles.csv.path=./db-dump/SampleData/um_role.csv
userAttributes.csv.path=./db-dump/SampleData/um_user_attribute.csv
userRoleMappings.csv.path=./db-dump/SampleData/um_user_role.csv

# ==== Output files ====
existingUsers.out.path=./db-dump/errors
errorLog.group.path=./db-dump/errors
errorLog.user.path=./db-dump/errors

# ==== WSO2 IS connection ====
baseUrl=https://localhost:9443

# Tenant domain (what you asked for)
tenantDomain=test.com

# SCIM credentials (tenant admin if needed)
scim.username=admin@test.com
scim.password=123456

# Target user store (you asked: EUM)
userStore.domain=EUM2

# Debug logging (true/false)
debug.enabled=true

#group batching
group.patch.batch.size=100


# Retry settings
retry.maxAttempts=3
retry.baseDelayMs=500
retry.maxDelayMs=5000
retry.jitterMs=200

Running the code

    #To build the code, 
         mvn clean package
         
    #Run the code
        mvn exec:java
