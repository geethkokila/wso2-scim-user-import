package com.user;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Base64;
import java.util.Properties;

public class CSVSCIMImporterV1 {

    // ======= LOAD CONFIG FROM config.properties =======
    private static final Properties CONFIG = loadConfig();

    // ======= CONFIG – FROM PROPERTIES =======
    private static final String USERS_CSV =
            required("users.csv.path");
    private static final String ROLES_CSV =
            required("roles.csv.path");
    private static final String USER_ATTRIBUTES_CSV =
            required("userAttributes.csv.path");
    private static final String USER_ROLE_MAPPING_CSV =
            required("userRoleMappings.csv.path");

    private static final String EXISTING_USERS_OUT =
            CONFIG.getProperty("existingUsers.out.path", "existing-users.csv");
    private static final String ERROR_LOG_OUT =
            CONFIG.getProperty("errorLog.out.path", "import-errors.csv");

    // WSO2 IS base URL
    private static final String BASE_URL =
            required("baseUrl");

    // Tenant domain (e.g. test.com)
    private static final String TENANT_DOMAIN =
            required("tenantDomain");

    // SCIM endpoints for tenant: /t/<tenant>/scim2/...
    private static final String SCIM_USERS_ENDPOINT =
            BASE_URL + "/t/" + TENANT_DOMAIN + "/scim2/Users";
    private static final String SCIM_GROUPS_ENDPOINT =
            BASE_URL + "/t/" + TENANT_DOMAIN + "/scim2/Groups";

    // Admin credentials for SCIM calls (tenant admin if needed)
    private static final String SCIM_USERNAME =
            required("scim.username");
    private static final String SCIM_PASSWORD =
            required("scim.password");

    // Target user store domain (EUM)
    private static final String USER_STORE_DOMAIN =
            CONFIG.getProperty("userStore.domain", "EUM");

    // Use same store for groups
    private static final String GROUP_STORE_DOMAIN = USER_STORE_DOMAIN;

    // Debug flag (prints request bodies, etc.)
    private static final boolean DEBUG =
            Boolean.parseBoolean(CONFIG.getProperty("debug.enabled", "true"));

    // HttpClient that trusts ALL SSL certificates (dev only!)
    private static final HttpClient HTTP_CLIENT;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Collect users that already existed in IS
    private static final List<ExistingUserRecord> existingUsers = new ArrayList<>();

    // Collect all errors to write at the end
    private static final List<ErrorRecord> errorRecords = new ArrayList<>();

    static {
        try {
            HTTP_CLIENT = createInsecureHttpClient();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create insecure HttpClient", e);
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("Loading CSV files...");

            Map<String, UserRow> users = loadUsers(USERS_CSV);
            Map<String, Map<String, String>> userAttributes = loadUserAttributes(USER_ATTRIBUTES_CSV);
            Map<String, RoleRow> roles = loadRoles(ROLES_CSV);
            List<UserRoleMapping> mappings = loadUserRoleMappings(USER_ROLE_MAPPING_CSV);

            System.out.println("Users: " + users.size());
            System.out.println("Roles: " + roles.size());
            System.out.println("User attributes keys: " + userAttributes.size());
            System.out.println("User-role mappings: " + mappings.size());

            // Map: um_user_id -> SCIM user id
            Map<String, String> umUserIdToScimId = new HashMap<>();

            // 1) Create users first (or reuse existing)
            System.out.println("Creating SCIM users (or reusing existing)...");
            for (UserRow user : users.values()) {
                Map<String, String> attrs = userAttributes.getOrDefault(user.umId, Collections.emptyMap());
                String scimUserId = null;
                try {
                    scimUserId = createScimUser(user, attrs);
                } catch (Exception e) {
                    String errorMsg = "Unexpected error in createScimUser: " + e.getMessage();
                    System.err.println(errorMsg);
                    errorRecords.add(ErrorRecord.forException(
                            "USER",
                            "CREATE_USER",
                            user.umId,
                            user.userName,
                            null,
                            null,
                            SCIM_USERS_ENDPOINT,
                            null,
                            null,
                            errorMsg
                    ));
                }

                if (scimUserId == null) {
                    System.out.println("Skipping roles for user " + user.userName + " (SCIM id is null)");
                    continue;
                }

                umUserIdToScimId.put(user.umId, scimUserId);
            }

            // 2) Build role -> member list based on mappings (using SCIM user IDs)
            Map<String, List<GroupMember>> roleIdToMembers = new HashMap<>();

            for (UserRoleMapping mapping : mappings) {
                String scimUserId = umUserIdToScimId.get(mapping.umUserId);
                if (scimUserId == null) {
                    System.out.println("WARN: No SCIM user for um_user_id=" + mapping.umUserId);
                    continue;
                }

                UserRow userRow = users.get(mapping.umUserId);
                Map<String, String> attrs = userAttributes.getOrDefault(mapping.umUserId, Collections.emptyMap());

                String screenName = attrs.getOrDefault("screenName",
                        userRow != null ? userRow.userName : ("user-" + mapping.umUserId));

                GroupMember member = new GroupMember(scimUserId, screenName);

                roleIdToMembers
                        .computeIfAbsent(mapping.umRoleId, k -> new ArrayList<>())
                        .add(member);
            }

            // 3) Ensure groups exist, then update them with members (PATCH)
            System.out.println("Creating/Updating SCIM groups (roles) with members...");
            for (RoleRow role : roles.values()) {
                List<GroupMember> members = roleIdToMembers.get(role.umId);
                if (members == null || members.isEmpty()) {
                    if (DEBUG) {
                        System.out.println("Skipping role " + role.roleName +
                                " (um_id=" + role.umId + ") - no members in mappings");
                    }
                    continue;
                }

                try {
                    ensureGroupAndAddMembers(role, members);
                } catch (Exception e) {
                    String errorMsg = "Unexpected error in ensureGroupAndAddMembers: " + e.getMessage();
                    System.err.println(errorMsg);
                    errorRecords.add(ErrorRecord.forException(
                            "GROUP",
                            "ENSURE_GROUP_AND_ADD_MEMBERS",
                            null,
                            null,
                            role.umId,
                            role.roleName,
                            SCIM_GROUPS_ENDPOINT,
                            null,
                            null,
                            errorMsg
                    ));
                }
            }

            // 4) Write existing users and errors to files
            writeExistingUsersToFile(EXISTING_USERS_OUT);
            writeErrorRecordsToFile(ERROR_LOG_OUT);

            System.out.println("Import finished.");
            System.out.println("Existing users written to: " + EXISTING_USERS_OUT);
            System.out.println("Errors written to: " + ERROR_LOG_OUT);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ===================================================================================
    // CONFIG LOADING
    // ===================================================================================

    private static Properties loadConfig() {
        Properties props = new Properties();
        try (InputStream in = CSVSCIMImporterV1.class
                .getClassLoader()
                .getResourceAsStream("config.properties")) {

            if (in == null) {
                throw new IllegalStateException(
                        "config.properties not found on classpath. " +
                                "Place it in src/main/resources.");
            }
            props.load(in);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load config.properties", e);
        }
        return props;
    }

    private static String required(String key) {
        String v = CONFIG.getProperty(key);
        if (v == null || v.trim().isEmpty()) {
            throw new IllegalStateException("Missing required property: " + key);
        }
        return v.trim();
    }

    // ===================================================================================
    // Insecure HttpClient (trust all certs) – DEV ONLY
    // ===================================================================================

    private static HttpClient createInsecureHttpClient() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new SecureRandom());

        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .build();
    }

    // ===================================================================================
    // CSV loading
    // ===================================================================================

    private static Map<String, UserRow> loadUsers(String path) throws IOException {
        Map<String, UserRow> map = new LinkedHashMap<>();

        try (Reader reader = new FileReader(path, StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT
                     .withFirstRecordAsHeader()
                     .withIgnoreSurroundingSpaces()
                     .parse(reader)) {

            for (CSVRecord record : parser) {
                UserRow u = new UserRow();
                u.umId = record.get("um_id").trim();
                u.userName = record.get("um_user_name").trim();
                u.password = normalizeNull(record.get("um_user_password"));
                u.salt = normalizeNull(record.get("um_salt_value"));
                u.requireChange = normalizeNull(record.get("um_require_change"));
                u.changedTime = normalizeNull(record.get("um_changed_time"));
                u.tenantId = normalizeNull(record.get("um_tenant_id"));

                map.put(u.umId, u);
            }
        }
        return map;
    }

    private static Map<String, RoleRow> loadRoles(String path) throws IOException {
        Map<String, RoleRow> map = new LinkedHashMap<>();

        try (Reader reader = new FileReader(path, StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT
                     .withFirstRecordAsHeader()
                     .withIgnoreSurroundingSpaces()
                     .parse(reader)) {

            for (CSVRecord record : parser) {
                RoleRow r = new RoleRow();
                r.umId = record.get("um_id").trim();
                r.roleName = record.get("um_role_name").trim();
                r.tenantId = normalizeNull(record.get("um_tenant_id"));
                r.sharedRole = normalizeNull(record.get("um_shared_role"));

                map.put(r.umId, r);
            }
        }
        return map;
    }

    private static Map<String, Map<String, String>> loadUserAttributes(String path) throws IOException {
        Map<String, Map<String, String>> map = new HashMap<>();

        try (Reader reader = new FileReader(path, StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT
                     .withFirstRecordAsHeader()
                     .withIgnoreSurroundingSpaces()
                     .parse(reader)) {

            for (CSVRecord record : parser) {
                String attrName = record.get("um_attr_name").trim();
                String attrValue = normalizeNull(record.get("um_attr_value"));
                String umUserId = record.get("um_user_id").trim();

                map.computeIfAbsent(umUserId, k -> new HashMap<>())
                        .put(attrName, attrValue);
            }
        }
        return map;
    }

    private static List<UserRoleMapping> loadUserRoleMappings(String path) throws IOException {
        List<UserRoleMapping> list = new ArrayList<>();

        try (Reader reader = new FileReader(path, StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT
                     .withFirstRecordAsHeader()
                     .withIgnoreSurroundingSpaces()
                     .parse(reader)) {

            for (CSVRecord record : parser) {
                UserRoleMapping m = new UserRoleMapping();
                m.umUserId = record.get("um_user_id").trim();
                m.umRoleId = record.get("um_role_id").trim();
                m.tenantId = normalizeNull(record.get("um_tenant_id"));
                list.add(m);
            }
        }
        return list;
    }

    private static String normalizeNull(String v) {
        if (v == null) return null;
        v = v.trim();
        if (v.equals("\\N") || v.isEmpty()) return null;
        return v;
    }

    // ===================================================================================
    // SCIM: Users (using only teacherid, givenName, screenName, mail, sn)
    // ===================================================================================

    private static String createScimUser(UserRow user, Map<String, String> attrs) {
        String scimId = null;
        String lastRequestBody = null;
        String lastResponseBody = null;
        int lastStatus = -1;

        try {
            // 1) Check if username already exists in IS (in EUM)
            scimId = findScimUserIdByUserName(user.userName);
            if (scimId != null) {
                if (DEBUG) {
                    System.out.println("User already exists in IS (EUM): " + user.userName +
                            " -> SCIM id = " + scimId);
                }
                existingUsers.add(new ExistingUserRecord(user.umId, user.userName, scimId));
                return scimId;
            }

            // 2) Build SCIM user create payload from user + attrs
            ObjectNode root = MAPPER.createObjectNode();

            ArrayNode schemas = MAPPER.createArrayNode();
            schemas.add("urn:ietf:params:scim:schemas:core:2.0:User");

            String enterpriseUrn = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
            boolean hasEnterpriseExtension = false;

            // Basic username & password; send to EUM user store
            String scimUserName = withUserStoreDomain(user.userName);
            root.put("userName", scimUserName);

            if (user.password != null && !user.password.isBlank()) {
                root.put("password", user.password);
            }

            // Keep old UM_ID for traceability
            root.put("externalId", user.umId);

            // ==== ONLY THESE ATTRIBUTES ARE USED NOW ====
            String teacherId      = attrs.get("teacherid");
            String givenNameAttr  = attrs.get("givenName");
            String familyNameAttr = attrs.get("sn");
            String screenNameAttr = attrs.get("screenName");
            String mail           = attrs.get("mail");
            // ============================================

            // NAME mapping (givenName, sn, screenName)
            String givenName = firstNonNull(givenNameAttr, screenNameAttr, user.userName);
            String familyName = firstNonNull(familyNameAttr, givenNameAttr, screenNameAttr, user.userName);

            ObjectNode name = MAPPER.createObjectNode();
            if (givenName != null) {
                name.put("givenName", givenName);
            }
            if (familyName != null) {
                name.put("familyName", familyName);
            }
            root.set("name", name);

            // EMAIL mapping (mail)
            if (mail != null && !mail.isBlank()) {
                ArrayNode emails = MAPPER.createArrayNode();
                ObjectNode emailWork = MAPPER.createObjectNode();
                emailWork.put("type", "work");
                emailWork.put("value", mail);
                emails.add(emailWork);
                root.set("emails", emails);
            }

            // Optionally store screenName as nickName
            if (screenNameAttr != null && !screenNameAttr.isBlank()) {
                root.put("nickName", screenNameAttr);
            }

            // Enterprise extension: ONLY teacherid -> employeeNumber
            ObjectNode enterprise = MAPPER.createObjectNode();
            if (teacherId != null && !teacherId.isBlank()) {
                enterprise.put("employeeNumber", teacherId);
                hasEnterpriseExtension = true;
            }

            if (hasEnterpriseExtension) {
                schemas.add(enterpriseUrn);
                root.set(enterpriseUrn, enterprise);
            }

            root.set("schemas", schemas);

            // Debug print request body
            lastRequestBody = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);

            if (DEBUG) {
                System.out.println("\n================ USER CREATE REQUEST ================");
                System.out.println("User UM_ID: " + user.umId +
                        "  USERNAME: " + user.userName +
                        "  SCIM userName: " + scimUserName);
                System.out.println(lastRequestBody);
                System.out.println("=====================================================\n");
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(SCIM_USERS_ENDPOINT))
                    .header("Content-Type", "application/scim+json")
                    .header("Accept", "application/scim+json")
                    .header("Authorization", basicAuth())
                    .POST(HttpRequest.BodyPublishers.ofString(lastRequestBody, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
            lastStatus = response.statusCode();
            lastResponseBody = response.body();

            if (lastStatus >= 200 && lastStatus < 300) {
                ObjectNode respJson = (ObjectNode) MAPPER.readTree(lastResponseBody);
                scimId = respJson.get("id").asText();
                if (DEBUG) {
                    System.out.println(" -> created SCIM user id=" + scimId);
                }
                return scimId;
            } else {
                System.err.println("Failed to create user " + user.userName + " HTTP " + lastStatus);
                System.err.println(lastResponseBody);
                errorRecords.add(new ErrorRecord(
                        "USER",
                        "CREATE_USER",
                        user.umId,
                        user.userName,
                        null,
                        null,
                        SCIM_USERS_ENDPOINT,
                        lastStatus,
                        lastRequestBody,
                        lastResponseBody,
                        "HTTP error"
                ));
                return null;
            }

        } catch (Exception e) {
            String msg = "Exception in createScimUser: " + e.getMessage();
            System.err.println(msg);
            errorRecords.add(new ErrorRecord(
                    "USER",
                    "CREATE_USER",
                    user.umId,
                    user.userName,
                    null,
                    null,
                    SCIM_USERS_ENDPOINT,
                    lastStatus,
                    lastRequestBody,
                    lastResponseBody,
                    msg
            ));
            return null;
        }
    }

    /**
     * Search SCIM by userName in EUM:
     * GET /scim2/Users?filter=userName eq "EUM/xxx"
     */
    private static String findScimUserIdByUserName(String userName) {
        String scimUserName = withUserStoreDomain(userName);
        String filter = "userName eq \"" + scimUserName.replace("\"", "\\\"") + "\"";
        String url = SCIM_USERS_ENDPOINT + "?filter=" +
                URLEncoder.encode(filter, StandardCharsets.UTF_8);

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/scim+json")
                    .header("Authorization", basicAuth())
                    .GET()
                    .build();

            HttpResponse<String> response =
                    HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            int status = response.statusCode();
            if (status >= 200 && status < 300) {
                JsonNode root = MAPPER.readTree(response.body());
                JsonNode totalResultsNode = root.get("totalResults");
                if (totalResultsNode != null && totalResultsNode.asInt() > 0) {
                    JsonNode resources = root.get("Resources");
                    if (resources != null && resources.isArray() && resources.size() > 0) {
                        JsonNode first = resources.get(0);
                        JsonNode idNode = first.get("id");
                        if (idNode != null && !idNode.asText().isBlank()) {
                            return idNode.asText();
                        }
                    }
                }
                return null;
            } else {
                System.err.println("User search failed for " + scimUserName + " HTTP " + status);
                System.err.println(response.body());
                errorRecords.add(new ErrorRecord(
                        "USER",
                        "SEARCH_USER",
                        null,
                        userName,
                        null,
                        null,
                        url,
                        status,
                        null,
                        response.body(),
                        "HTTP error in user search"
                ));
                return null;
            }
        } catch (Exception e) {
            String msg = "Exception in findScimUserIdByUserName: " + e.getMessage();
            System.err.println(msg);
            errorRecords.add(new ErrorRecord(
                    "USER",
                    "SEARCH_USER",
                    null,
                    userName,
                    null,
                    null,
                    null,
                    -1,
                    null,
                    null,
                    msg
            ));
            return null;
        }
    }

    // ===================================================================================
    // SCIM: Groups (Roles) - create/update with members in same user store
    // ===================================================================================

    private static void ensureGroupAndAddMembers(RoleRow role, List<GroupMember> members) {
        String groupId = findScimGroupIdByDisplayName(role.roleName);

        if (groupId == null) {
            groupId = createScimGroup(role);
            if (groupId == null) {
                System.err.println("Cannot patch members for role " + role.roleName +
                        " because group creation failed.");
                return;
            }
        }

        patchGroupAddMembers(groupId, role, members);
    }

    private static String findScimGroupIdByDisplayName(String roleName) {
        String displayName = withGroupStoreDomain(roleName);
        String filter = "displayName eq \"" + displayName.replace("\"", "\\\"") + "\"";
        String url = SCIM_GROUPS_ENDPOINT + "?filter=" +
                URLEncoder.encode(filter, StandardCharsets.UTF_8);

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/scim+json")
                    .header("Authorization", basicAuth())
                    .GET()
                    .build();

            HttpResponse<String> response =
                    HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            int status = response.statusCode();
            if (status >= 200 && status < 300) {
                JsonNode root = MAPPER.readTree(response.body());
                JsonNode totalResultsNode = root.get("totalResults");
                if (totalResultsNode != null && totalResultsNode.asInt() > 0) {
                    JsonNode resources = root.get("Resources");
                    if (resources != null && resources.isArray() && resources.size() > 0) {
                        JsonNode first = resources.get(0);
                        JsonNode idNode = first.get("id");
                        if (idNode != null && !idNode.asText().isBlank()) {
                            return idNode.asText();
                        }
                    }
                }
                return null;
            } else {
                System.err.println("Group search failed for " + displayName + " HTTP " + status);
                System.err.println(response.body());
                errorRecords.add(new ErrorRecord(
                        "GROUP",
                        "SEARCH_GROUP",
                        null,
                        null,
                        null,
                        roleName,
                        url,
                        status,
                        null,
                        response.body(),
                        "HTTP error in group search"
                ));
                return null;
            }
        } catch (Exception e) {
            String msg = "Exception in findScimGroupIdByDisplayName: " + e.getMessage();
            System.err.println(msg);
            errorRecords.add(new ErrorRecord(
                    "GROUP",
                    "SEARCH_GROUP",
                    null,
                    null,
                    null,
                    roleName,
                    null,
                    -1,
                    null,
                    null,
                    msg
            ));
            return null;
        }
    }

    private static String createScimGroup(RoleRow role) {
        String lastRequestBody = null;
        String lastResponseBody = null;
        int lastStatus = -1;

        try {
            ObjectNode root = MAPPER.createObjectNode();

            ArrayNode schemas = MAPPER.createArrayNode();
            schemas.add("urn:ietf:params:scim:schemas:core:2.0:Group");
            root.set("schemas", schemas);

            // Create group in same user store as users: EUM/<roleName>
            String displayName = withGroupStoreDomain(role.roleName);
            root.put("displayName", displayName);

            lastRequestBody = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);

            if (DEBUG) {
                System.out.println("\n================ GROUP CREATE (EMPTY) REQUEST ================");
                System.out.println("Role UM_ID: " + role.umId +
                        "  ROLE NAME: " + role.roleName +
                        "  DISPLAY NAME: " + displayName);
                System.out.println(lastRequestBody);
                System.out.println("================================================================\n");
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(SCIM_GROUPS_ENDPOINT))
                    .header("Content-Type", "application/scim+json")
                    .header("Accept", "application/scim+json")
                    .header("Authorization", basicAuth())
                    .POST(HttpRequest.BodyPublishers.ofString(lastRequestBody, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
            lastStatus = response.statusCode();
            lastResponseBody = response.body();

            if (lastStatus >= 200 && lastStatus < 300) {
                ObjectNode respJson = (ObjectNode) MAPPER.readTree(lastResponseBody);
                String scimGroupId = respJson.get("id").asText();
                if (DEBUG) {
                    System.out.println(" -> created SCIM group id=" + scimGroupId +
                            " displayName=" + displayName);
                }
                return scimGroupId;
            } else {
                System.err.println("Failed to create group " + displayName + " HTTP " + lastStatus);
                System.err.println(lastResponseBody);
                errorRecords.add(new ErrorRecord(
                        "GROUP",
                        "CREATE_GROUP",
                        null,
                        null,
                        role.umId,
                        role.roleName,
                        SCIM_GROUPS_ENDPOINT,
                        lastStatus,
                        lastRequestBody,
                        lastResponseBody,
                        "HTTP error"
                ));
                return null;
            }
        } catch (Exception e) {
            String msg = "Exception in createScimGroup: " + e.getMessage();
            System.err.println(msg);
            errorRecords.add(new ErrorRecord(
                    "GROUP",
                    "CREATE_GROUP",
                    null,
                    null,
                    role.umId,
                    role.roleName,
                    SCIM_GROUPS_ENDPOINT,
                    lastStatus,
                    lastRequestBody,
                    lastResponseBody,
                    msg
            ));
            return null;
        }
    }

    private static void patchGroupAddMembers(String groupId, RoleRow role, List<GroupMember> members) {
        String lastRequestBody = null;
        String lastResponseBody = null;
        int lastStatus = -1;

        try {
            ObjectNode root = MAPPER.createObjectNode();

            ArrayNode schemas = MAPPER.createArrayNode();
            schemas.add("urn:ietf:params:scim:api:messages:2.0:PatchOp");
            root.set("schemas", schemas);

            ArrayNode operations = MAPPER.createArrayNode();
            ObjectNode op = MAPPER.createObjectNode();
            op.put("op", "add");
            op.put("path", "members");

            ArrayNode valueArray = MAPPER.createArrayNode();
            for (GroupMember m : members) {
                ObjectNode mem = MAPPER.createObjectNode();
                mem.put("value", m.scimUserId);
                mem.put("display", m.displayName);
                valueArray.add(mem);
            }
            op.set("value", valueArray);
            operations.add(op);
            root.set("Operations", operations);

            lastRequestBody = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);

            String groupUrl = SCIM_GROUPS_ENDPOINT + "/" + groupId;

            if (DEBUG) {
                System.out.println("\n================ GROUP PATCH (ADD MEMBERS) REQUEST ================");
                System.out.println("Role UM_ID: " + role.umId + "  ROLE NAME: " + role.roleName);
                System.out.println("Group SCIM ID: " + groupId + "  Members: " + members.size());
                System.out.println(lastRequestBody);
                System.out.println("===================================================================\n");
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(groupUrl))
                    .header("Content-Type", "application/scim+json")
                    .header("Accept", "application/scim+json")
                    .header("Authorization", basicAuth())
                    .method("PATCH", HttpRequest.BodyPublishers.ofString(lastRequestBody, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
            lastStatus = response.statusCode();
            lastResponseBody = response.body();

            if (lastStatus >= 200 && lastStatus < 300) {
                if (DEBUG) {
                    System.out.println(" -> patched group " + groupId + " with " + members.size() + " members");
                }
            } else {
                System.err.println("Failed to PATCH members to group " + role.roleName + " HTTP " + lastStatus);
                System.err.println(lastResponseBody);
                errorRecords.add(new ErrorRecord(
                        "GROUP",
                        "PATCH_GROUP_ADD_MEMBERS",
                        null,
                        null,
                        role.umId,
                        role.roleName,
                        groupUrl,
                        lastStatus,
                        lastRequestBody,
                        lastResponseBody,
                        "HTTP error"
                ));
            }
        } catch (Exception e) {
            String msg = "Exception in patchGroupAddMembers: " + e.getMessage();
            System.err.println(msg);
            errorRecords.add(new ErrorRecord(
                    "GROUP",
                    "PATCH_GROUP_ADD_MEMBERS",
                    null,
                    null,
                    role.umId,
                    role.roleName,
                    SCIM_GROUPS_ENDPOINT + "/" + groupId,
                    lastStatus,
                    lastRequestBody,
                    lastResponseBody,
                    msg
            ));
        }
    }

    // ===================================================================================
    // Write existing users and error log to files
    // ===================================================================================

    private static void writeExistingUsersToFile(String filePath) {
        if (existingUsers.isEmpty()) {
            if (DEBUG) {
                System.out.println("No existing users to write.");
            }
            return;
        }

        Path path = Path.of(filePath);
        try (BufferedWriter writer = Files.newBufferedWriter(
                path,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
        )) {
            writer.write("um_id,userName,scimId");
            writer.newLine();

            for (ExistingUserRecord r : existingUsers) {
                writer.write(String.join(",",
                        safeCsv(r.umId),
                        safeCsv(r.userName),
                        safeCsv(r.scimId)
                ));
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println("Failed to write existing users file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void writeErrorRecordsToFile(String filePath) {
        if (errorRecords.isEmpty()) {
            if (DEBUG) {
                System.out.println("No errors to write.");
            }
            return;
        }

        Path path = Path.of(filePath);
        try (BufferedWriter writer = Files.newBufferedWriter(
                path,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
        )) {
            writer.write("type,operation,um_id,userName,role_id,roleName,endpoint,httpStatus,requestBody,responseBody,errorMessage");
            writer.newLine();

            for (ErrorRecord r : errorRecords) {
                writer.write(String.join(",",
                        safeCsv(r.type),
                        safeCsv(r.operation),
                        safeCsv(r.umId),
                        safeCsv(r.userName),
                        safeCsv(r.roleId),
                        safeCsv(r.roleName),
                        safeCsv(r.endpoint),
                        r.httpStatus == null ? "" : r.httpStatus.toString(),
                        safeCsv(r.requestBody),
                        safeCsv(r.responseBody),
                        safeCsv(r.errorMessage)
                ));
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println("Failed to write error log file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String safeCsv(String v) {
        if (v == null) return "";
        v = v.replace("\n", " ").replace("\r", " ");
        return v;
    }

    // ===================================================================================
    // Helpers / Models
    // ===================================================================================

    private static String basicAuth() {
        String creds = SCIM_USERNAME + ":" + SCIM_PASSWORD;
        String base64 = Base64.getEncoder()
                .encodeToString(creds.getBytes(StandardCharsets.UTF_8));
        return "Basic " + base64;
    }

    private static String firstNonNull(String... values) {
        if (values == null) return null;
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    private static String withUserStoreDomain(String userName) {
        if (userName == null) return null;
        if (userName.contains("/")) {
            return userName;
        }
        return USER_STORE_DOMAIN + "/" + userName;
    }

    private static String withGroupStoreDomain(String roleName) {
        if (roleName == null) return null;
        if (roleName.contains("/")) {
            // Already has a domain prefix
            return roleName;
        }
        return GROUP_STORE_DOMAIN + "/" + roleName;
    }

    private static class UserRow {
        String umId;
        String userName;
        String password;
        String salt;
        String requireChange;
        String changedTime;
        String tenantId;
    }

    private static class RoleRow {
        String umId;
        String roleName;
        String tenantId;
        String sharedRole;
    }

    private static class UserRoleMapping {
        String umUserId;
        String umRoleId;
        String tenantId;
    }

    private static class GroupMember {
        final String scimUserId;
        final String displayName;

        GroupMember(String scimUserId, String displayName) {
            this.scimUserId = scimUserId;
            this.displayName = displayName;
        }
    }

    private static class ExistingUserRecord {
        final String umId;
        final String userName;
        final String scimId;

        ExistingUserRecord(String umId, String userName, String scimId) {
            this.umId = umId;
            this.userName = userName;
            this.scimId = scimId;
        }
    }

    private static class ErrorRecord {
        final String type;
        final String operation;
        final String umId;
        final String userName;
        final String roleId;
        final String roleName;
        final String endpoint;
        final Integer httpStatus;
        final String requestBody;
        final String responseBody;
        final String errorMessage;

        ErrorRecord(String type, String operation,
                    String umId, String userName,
                    String roleId, String roleName,
                    String endpoint,
                    Integer httpStatus,
                    String requestBody,
                    String responseBody,
                    String errorMessage) {
            this.type = type;
            this.operation = operation;
            this.umId = umId;
            this.userName = userName;
            this.roleId = roleId;
            this.roleName = roleName;
            this.endpoint = endpoint;
            this.httpStatus = httpStatus;
            this.requestBody = requestBody;
            this.responseBody = responseBody;
            this.errorMessage = errorMessage;
        }

        static ErrorRecord forException(String type, String operation,
                                        String umId, String userName,
                                        String roleId, String roleName,
                                        String endpoint,
                                        String requestBody,
                                        String responseBody,
                                        String errorMessage) {
            return new ErrorRecord(type, operation, umId, userName,
                    roleId, roleName, endpoint, null,
                    requestBody, responseBody, errorMessage);
        }
    }
}
