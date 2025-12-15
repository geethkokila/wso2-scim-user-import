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
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.Base64;
import java.util.Properties;

public class CSVSCIMImporterV1 {

    // ======= LOAD CONFIG =======
    private static final Properties CONFIG = loadConfig();

    // ======= CSV PATHS =======
    private static final String USERS_CSV = required("users.csv.path");
    private static final String ROLES_CSV = required("roles.csv.path");
    private static final String USER_ATTRIBUTES_CSV = required("userAttributes.csv.path");
    private static final String USER_ROLE_MAPPING_CSV = required("userRoleMappings.csv.path");

    // Output files
    private static final String EXISTING_USERS_OUT =
            CONFIG.getProperty("existingUsers.out.path", "existing-users.csv");

    private static final String ERROR_LOG_USER_OUT =
            CONFIG.getProperty("errorLog.user.path", "import-errors-user.csv");
    private static final String ERROR_LOG_GROUP_OUT =
            CONFIG.getProperty("errorLog.group.path", "import-errors-group.csv");

    // WSO2 IS base URL + tenant
    private static final String BASE_URL = required("baseUrl");
    private static final String TENANT_DOMAIN = required("tenantDomain");

    private static final String SCIM_USERS_ENDPOINT =
            BASE_URL + "/t/" + TENANT_DOMAIN + "/scim2/Users";
    private static final String SCIM_GROUPS_ENDPOINT =
            BASE_URL + "/t/" + TENANT_DOMAIN + "/scim2/Groups";

    // SCIM auth
    private static final String SCIM_USERNAME = required("scim.username");
    private static final String SCIM_PASSWORD = required("scim.password");

    // Target userstore
    private static final String USER_STORE_DOMAIN =
            CONFIG.getProperty("userStore.domain", "EUM");
    private static final String GROUP_STORE_DOMAIN = USER_STORE_DOMAIN;

    // Group patch batch size
    private static final int GROUP_PATCH_BATCH_SIZE =
            Integer.parseInt(CONFIG.getProperty("group.patch.batch.size", "200"));

    // Retry settings
    private static final int RETRY_MAX_ATTEMPTS =
            Integer.parseInt(CONFIG.getProperty("retry.maxAttempts", "3"));
    private static final long RETRY_BASE_DELAY_MS =
            Long.parseLong(CONFIG.getProperty("retry.baseDelayMs", "500"));
    private static final long RETRY_MAX_DELAY_MS =
            Long.parseLong(CONFIG.getProperty("retry.maxDelayMs", "5000"));
    private static final long RETRY_JITTER_MS =
            Long.parseLong(CONFIG.getProperty("retry.jitterMs", "200"));

    // Debug
    private static final boolean DEBUG =
            Boolean.parseBoolean(CONFIG.getProperty("debug.enabled", "true"));

    // HTTP + JSON
    private static final HttpClient HTTP_CLIENT;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Track existing users (still useful)
    private static final List<ExistingUserRecord> existingUsers = new ArrayList<>();

    // Error log writers (init-on-first-write)
    private static boolean userErrorHeaderWritten = false;
    private static boolean groupErrorHeaderWritten = false;

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

            // 1) Ensure all groups exist first
            Map<String, String> roleIdToGroupId = new HashMap<>();
            System.out.println("Ensuring SCIM groups exist...");
            for (RoleRow role : roles.values()) {
                String groupId = findScimGroupIdByDisplayName(role.roleName);
                if (groupId == null) {
                    groupId = createScimGroup(role);
                }
                if (groupId != null) {
                    roleIdToGroupId.put(role.umId, groupId);
                }
            }

            // 2) user -> roles map
            Map<String, List<RoleRow>> userIdToRoles = new HashMap<>();
            for (UserRoleMapping mapping : mappings) {
                RoleRow role = roles.get(mapping.umRoleId);
                if (role == null) continue;
                userIdToRoles.computeIfAbsent(mapping.umUserId, k -> new ArrayList<>()).add(role);
            }

            // 3) For each user: create/reuse user, then patch into groups
            System.out.println("Creating SCIM users and patching them into groups...");
            for (UserRow user : users.values()) {
                Map<String, String> attrs = userAttributes.getOrDefault(user.umId, Collections.emptyMap());

                String scimUserId = createScimUser(user, attrs);
                if (scimUserId == null) {
                    System.out.println("Skipping group patching for user " + user.userName +
                            " (SCIM id is null)");
                    continue;
                }

                List<RoleRow> userRoles = userIdToRoles.get(user.umId);
                if (userRoles == null || userRoles.isEmpty()) continue;

                String screenName = attrs.getOrDefault("screenName", user.userName);
                GroupMember member = new GroupMember(scimUserId, screenName);

                for (RoleRow role : userRoles) {
                    String groupId = roleIdToGroupId.get(role.umId);
                    if (groupId == null) {
                        logErrorImmediately(new ErrorRecord(
                                nowIsoUtc(),
                                "GROUP",
                                "PATCH_GROUP_ADD_MEMBER",
                                1,
                                RETRY_MAX_ATTEMPTS,
                                0,
                                "missingGroupId",
                                user.umId,
                                user.userName,
                                role.umId,
                                role.roleName,
                                SCIM_GROUPS_ENDPOINT,
                                null,
                                null,
                                null,
                                "No SCIM group id found for role"
                        ));
                        continue;
                    }
                    patchGroupAddMembers(groupId, role, Collections.singletonList(member), user);
                }
            }

            // existing users output
            writeExistingUsersToFile(EXISTING_USERS_OUT);
            System.out.println("Import finished.");
            System.out.println("Existing users written to: " + EXISTING_USERS_OUT);
            System.out.println("Errors (USER) written to: " + ERROR_LOG_USER_OUT);
            System.out.println("Errors (GROUP) written to: " + ERROR_LOG_GROUP_OUT);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ===================================================================================
    // CONFIG LOADING (supports -Dconfig.file or CONFIG_FILE, then classpath fallback)
    // ===================================================================================

    private static Properties loadConfig() {
        Properties props = new Properties();

        String configPath = System.getProperty("config.file");
        if (configPath == null || configPath.isBlank()) {
            configPath = System.getenv("CONFIG_FILE");
        }

        try {
            if (configPath != null && !configPath.isBlank()) {
                System.out.println("Loading config.properties from path: " + configPath);
                try (InputStream in = Files.newInputStream(Path.of(configPath))) {
                    props.load(in);
                }
            } else {
                System.out.println("Loading config.properties from classpath");
                try (InputStream in = CSVSCIMImporterV1.class.getClassLoader().getResourceAsStream("config.properties")) {
                    if (in == null) {
                        throw new IllegalStateException(
                                "config.properties not found on classpath and no config.file/CONFIG_FILE specified."
                        );
                    }
                    props.load(in);
                }
            }
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
             CSVParser parser = CSVFormat.DEFAULT.withFirstRecordAsHeader().withIgnoreSurroundingSpaces().parse(reader)) {

            for (CSVRecord record : parser) {
                UserRow u = new UserRow();
                u.umId = record.get("um_id").trim();
                u.userName = record.get("um_user_name").trim();
                u.password = normalizeNull(record.get("um_user_password"));
                u.tenantId = normalizeNull(record.get("um_tenant_id"));
                map.put(u.umId, u);
            }
        }
        return map;
    }

    private static Map<String, RoleRow> loadRoles(String path) throws IOException {
        Map<String, RoleRow> map = new LinkedHashMap<>();
        try (Reader reader = new FileReader(path, StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT.withFirstRecordAsHeader().withIgnoreSurroundingSpaces().parse(reader)) {

            for (CSVRecord record : parser) {
                RoleRow r = new RoleRow();
                r.umId = record.get("um_id").trim();
                r.roleName = record.get("um_role_name").trim();
                map.put(r.umId, r);
            }
        }
        return map;
    }

    private static Map<String, Map<String, String>> loadUserAttributes(String path) throws IOException {
        Map<String, Map<String, String>> map = new HashMap<>();
        try (Reader reader = new FileReader(path, StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT.withFirstRecordAsHeader().withIgnoreSurroundingSpaces().parse(reader)) {

            for (CSVRecord record : parser) {
                String attrName = record.get("um_attr_name").trim();
                String attrValue = normalizeNull(record.get("um_attr_value"));
                String umUserId = record.get("um_user_id").trim();
                map.computeIfAbsent(umUserId, k -> new HashMap<>()).put(attrName, attrValue);
            }
        }
        return map;
    }

    private static List<UserRoleMapping> loadUserRoleMappings(String path) throws IOException {
        List<UserRoleMapping> list = new ArrayList<>();
        try (Reader reader = new FileReader(path, StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT.withFirstRecordAsHeader().withIgnoreSurroundingSpaces().parse(reader)) {

            for (CSVRecord record : parser) {
                UserRoleMapping m = new UserRoleMapping();
                m.umUserId = record.get("um_user_id").trim();
                m.umRoleId = record.get("um_role_id").trim();
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
    // SCIM: Users (teacherid, givenName, screenName, mail, sn)
    // ===================================================================================

    private static String createScimUser(UserRow user, Map<String, String> attrs) {
        // 1) Check if exists
        String existingId = findScimUserIdByUserName(user.userName);
        if (existingId != null) {
            existingUsers.add(new ExistingUserRecord(user.umId, user.userName, existingId));
            return existingId;
        }

        String teacherId = attrs.get("teacherid");
        String givenNameAttr = attrs.get("givenName");
        String familyNameAttr = attrs.get("sn");
        String screenNameAttr = attrs.get("screenName");
        String mail = attrs.get("mail");

        ObjectNode root = MAPPER.createObjectNode();

        ArrayNode schemas = MAPPER.createArrayNode();
        schemas.add("urn:ietf:params:scim:schemas:core:2.0:User");

        String enterpriseUrn = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

        String scimUserName = withUserStoreDomain(user.userName);
        root.put("userName", scimUserName);

        if (user.password != null && !user.password.isBlank()) {
            root.put("password", user.password);
        }

        // externalId MUST be teacherid (if missing, we do not set it)
        if (teacherId != null && !teacherId.isBlank()) {
            root.put("externalId", teacherId);
        }

        // name
        String givenName = firstNonNull(givenNameAttr, screenNameAttr, user.userName);
        String familyName = firstNonNull(familyNameAttr, givenNameAttr, screenNameAttr, user.userName);

        ObjectNode name = MAPPER.createObjectNode();
        name.put("givenName", givenName);
        name.put("familyName", familyName);
        root.set("name", name);

        // primary email only if contains "@"
        if (mail != null && !mail.isBlank() && mail.contains("@")) {
            ArrayNode emails = MAPPER.createArrayNode();
            ObjectNode primaryEmail = MAPPER.createObjectNode();
            primaryEmail.put("value", mail);
            primaryEmail.put("primary", true);
            emails.add(primaryEmail);
            root.set("emails", emails);
        } else if (DEBUG) {
            System.out.println("Skipping email for user (invalid or missing '@'): " + mail);
        }

        // nickName from screenName
        if (screenNameAttr != null && !screenNameAttr.isBlank()) {
            root.put("nickName", screenNameAttr);
        }

        // enterprise extension with employeeNumber = teacherid
        if (teacherId != null && !teacherId.isBlank()) {
            ObjectNode enterprise = MAPPER.createObjectNode();
            enterprise.put("employeeNumber", teacherId);
            schemas.add(enterpriseUrn);
            root.set(enterpriseUrn, enterprise);
        }

        root.set("schemas", schemas);

        String requestBody;
        try {
            requestBody = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            logErrorImmediately(new ErrorRecord(
                    nowIsoUtc(),
                    "USER",
                    "CREATE_USER",
                    1,
                    RETRY_MAX_ATTEMPTS,
                    0,
                    "serializationError",
                    user.umId,
                    user.userName,
                    null,
                    null,
                    SCIM_USERS_ENDPOINT,
                    null,
                    null,
                    null,
                    e.getMessage()
            ));
            return null;
        }

        if (DEBUG) {
            System.out.println("\n================ USER CREATE REQUEST ================");
            System.out.println("User UM_ID          : " + user.umId);
            System.out.println("Database userName   : " + user.userName);
            System.out.println("SCIM userName       : " + scimUserName);
            System.out.println("teacherid (attr)    : " + teacherId);
            System.out.println("externalId (SCIM)   : " + teacherId);
            System.out.println("givenName (attr)    : " + givenNameAttr);
            System.out.println("sn (attr)           : " + familyNameAttr);
            System.out.println("screenName (attr)   : " + screenNameAttr);
            System.out.println("mail (attr)         : " + mail);
            System.out.println("------------------- SCIM JSON BODY -----------------");
            System.out.println(requestBody);
            System.out.println("=====================================================\n");
        }

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(SCIM_USERS_ENDPOINT))
                .header("Content-Type", "application/scim+json")
                .header("Accept", "application/scim+json")
                .header("Authorization", basicAuth())
                .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                .build();

        RetryResult<HttpResponse<String>> rr = sendWithRetry(req, "USER", "CREATE_USER", user, null, null, requestBody);

        if (rr.response != null && rr.response.statusCode() >= 200 && rr.response.statusCode() < 300) {
            try {
                ObjectNode respJson = (ObjectNode) MAPPER.readTree(rr.response.body());
                return respJson.get("id").asText();
            } catch (Exception e) {
                logErrorImmediately(new ErrorRecord(
                        nowIsoUtc(),
                        "USER",
                        "CREATE_USER_PARSE_RESPONSE",
                        rr.attempt,
                        rr.maxAttempts,
                        rr.lastBackoffMs,
                        rr.retryableReason,
                        user.umId,
                        user.userName,
                        null,
                        null,
                        SCIM_USERS_ENDPOINT,
                        rr.response.statusCode(),
                        requestBody,
                        rr.response.body(),
                        e.getMessage()
                ));
                return null;
            }
        }

        // Non-success already logged by sendWithRetry (final failure), return null
        return null;
    }

    private static String findScimUserIdByUserName(String userName) {
        String scimUserName = withUserStoreDomain(userName);
        String filter = "userName eq \"" + scimUserName.replace("\"", "\\\"") + "\"";
        String url = SCIM_USERS_ENDPOINT + "?filter=" + URLEncoder.encode(filter, StandardCharsets.UTF_8);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", "application/scim+json")
                .header("Authorization", basicAuth())
                .GET()
                .build();

        RetryResult<HttpResponse<String>> rr = sendWithRetry(req, "USER", "SEARCH_USER", null, null, userName, null);

        if (rr.response != null && rr.response.statusCode() >= 200 && rr.response.statusCode() < 300) {
            try {
                JsonNode root = MAPPER.readTree(rr.response.body());
                JsonNode totalResultsNode = root.get("totalResults");
                if (totalResultsNode != null && totalResultsNode.asInt() > 0) {
                    JsonNode resources = root.get("Resources");
                    if (resources != null && resources.isArray() && resources.size() > 0) {
                        JsonNode idNode = resources.get(0).get("id");
                        if (idNode != null && !idNode.asText().isBlank()) return idNode.asText();
                    }
                }
            } catch (Exception e) {
                logErrorImmediately(new ErrorRecord(
                        nowIsoUtc(),
                        "USER",
                        "SEARCH_USER_PARSE_RESPONSE",
                        rr.attempt,
                        rr.maxAttempts,
                        rr.lastBackoffMs,
                        rr.retryableReason,
                        null,
                        userName,
                        null,
                        null,
                        url,
                        rr.response.statusCode(),
                        null,
                        rr.response.body(),
                        e.getMessage()
                ));
            }
        }
        return null;
    }

    // ===================================================================================
    // SCIM: Groups (create then patch per user)
    // ===================================================================================

    private static String findScimGroupIdByDisplayName(String roleName) {
        String displayName = withGroupStoreDomain(roleName);
        String filter = "displayName eq \"" + displayName.replace("\"", "\\\"") + "\"";
        String url = SCIM_GROUPS_ENDPOINT + "?filter=" + URLEncoder.encode(filter, StandardCharsets.UTF_8);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", "application/scim+json")
                .header("Authorization", basicAuth())
                .GET()
                .build();

        RetryResult<HttpResponse<String>> rr = sendWithRetry(req, "GROUP", "SEARCH_GROUP", null, roleName, null, null);

        if (rr.response != null && rr.response.statusCode() >= 200 && rr.response.statusCode() < 300) {
            try {
                JsonNode root = MAPPER.readTree(rr.response.body());
                JsonNode totalResultsNode = root.get("totalResults");
                if (totalResultsNode != null && totalResultsNode.asInt() > 0) {
                    JsonNode resources = root.get("Resources");
                    if (resources != null && resources.isArray() && resources.size() > 0) {
                        JsonNode idNode = resources.get(0).get("id");
                        if (idNode != null && !idNode.asText().isBlank()) return idNode.asText();
                    }
                }
            } catch (Exception e) {
                logErrorImmediately(new ErrorRecord(
                        nowIsoUtc(),
                        "GROUP",
                        "SEARCH_GROUP_PARSE_RESPONSE",
                        rr.attempt,
                        rr.maxAttempts,
                        rr.lastBackoffMs,
                        rr.retryableReason,
                        null,
                        null,
                        null,
                        roleName,
                        url,
                        rr.response.statusCode(),
                        null,
                        rr.response.body(),
                        e.getMessage()
                ));
            }
        }
        return null;
    }

    private static String createScimGroup(RoleRow role) {
        ObjectNode root = MAPPER.createObjectNode();
        ArrayNode schemas = MAPPER.createArrayNode();
        schemas.add("urn:ietf:params:scim:schemas:core:2.0:Group");
        root.set("schemas", schemas);

        String displayName = withGroupStoreDomain(role.roleName);
        root.put("displayName", displayName);

        String requestBody;
        try {
            requestBody = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            logErrorImmediately(new ErrorRecord(
                    nowIsoUtc(),
                    "GROUP",
                    "CREATE_GROUP_SERIALIZE",
                    1,
                    RETRY_MAX_ATTEMPTS,
                    0,
                    "serializationError",
                    null,
                    null,
                    role.umId,
                    role.roleName,
                    SCIM_GROUPS_ENDPOINT,
                    null,
                    null,
                    null,
                    e.getMessage()
            ));
            return null;
        }

        if (DEBUG) {
            System.out.println("\n================ GROUP CREATE REQUEST ================");
            System.out.println("Role UM_ID: " + role.umId + " ROLE NAME: " + role.roleName);
            System.out.println(requestBody);
            System.out.println("=====================================================\n");
        }

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(SCIM_GROUPS_ENDPOINT))
                .header("Content-Type", "application/scim+json")
                .header("Accept", "application/scim+json")
                .header("Authorization", basicAuth())
                .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                .build();

        RetryResult<HttpResponse<String>> rr = sendWithRetry(req, "GROUP", "CREATE_GROUP", null, role.roleName, null, requestBody);

        if (rr.response != null && rr.response.statusCode() >= 200 && rr.response.statusCode() < 300) {
            try {
                ObjectNode respJson = (ObjectNode) MAPPER.readTree(rr.response.body());
                return respJson.get("id").asText();
            } catch (Exception e) {
                logErrorImmediately(new ErrorRecord(
                        nowIsoUtc(),
                        "GROUP",
                        "CREATE_GROUP_PARSE_RESPONSE",
                        rr.attempt,
                        rr.maxAttempts,
                        rr.lastBackoffMs,
                        rr.retryableReason,
                        null,
                        null,
                        role.umId,
                        role.roleName,
                        SCIM_GROUPS_ENDPOINT,
                        rr.response.statusCode(),
                        requestBody,
                        rr.response.body(),
                        e.getMessage()
                ));
            }
        }
        return null;
    }

    private static void patchGroupAddMembers(String groupId, RoleRow role, List<GroupMember> members, UserRow userForContext) {
        if (members == null || members.isEmpty()) return;

        int total = members.size();
        int batchSize = GROUP_PATCH_BATCH_SIZE;

        for (int start = 0; start < total; start += batchSize) {
            int end = Math.min(start + batchSize, total);
            List<GroupMember> batch = members.subList(start, end);
            patchGroupAddMembersBatch(groupId, role, batch, userForContext);
        }
    }

    private static void patchGroupAddMembersBatch(String groupId, RoleRow role, List<GroupMember> batch, UserRow userForContext) {
        ObjectNode root = MAPPER.createObjectNode();
        ArrayNode schemas = MAPPER.createArrayNode();
        schemas.add("urn:ietf:params:scim:api:messages:2.0:PatchOp");
        root.set("schemas", schemas);

        ArrayNode operations = MAPPER.createArrayNode();
        ObjectNode op = MAPPER.createObjectNode();
        op.put("op", "add");
        op.put("path", "members");

        ArrayNode valueArray = MAPPER.createArrayNode();
        for (GroupMember m : batch) {
            ObjectNode mem = MAPPER.createObjectNode();
            mem.put("value", m.scimUserId);
            mem.put("display", m.displayName);
            valueArray.add(mem);
        }
        op.set("value", valueArray);
        operations.add(op);

        root.set("Operations", operations);

        String requestBody;
        try {
            requestBody = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            logErrorImmediately(new ErrorRecord(
                    nowIsoUtc(),
                    "GROUP",
                    "PATCH_GROUP_SERIALIZE",
                    1,
                    RETRY_MAX_ATTEMPTS,
                    0,
                    "serializationError",
                    userForContext != null ? userForContext.umId : null,
                    userForContext != null ? userForContext.userName : null,
                    role.umId,
                    role.roleName,
                    SCIM_GROUPS_ENDPOINT + "/" + groupId,
                    null,
                    null,
                    null,
                    e.getMessage()
            ));
            return;
        }

        if (DEBUG) {
            System.out.println("\n================ GROUP PATCH ADD MEMBER ================");
            System.out.println("GroupId: " + groupId + " Role: " + role.roleName + " Members: " + batch.size());
            System.out.println(requestBody);
            System.out.println("========================================================\n");
        }

        String groupUrl = SCIM_GROUPS_ENDPOINT + "/" + groupId;

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(groupUrl))
                .header("Content-Type", "application/scim+json")
                .header("Accept", "application/scim+json")
                .header("Authorization", basicAuth())
                .method("PATCH", HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                .build();

        sendWithRetry(req, "GROUP", "PATCH_GROUP_ADD_MEMBER", userForContext, role.roleName, null, requestBody);
        // Any final failure is logged inside sendWithRetry
    }

    // ===================================================================================
    // Retry wrapper + immediate error logging
    // ===================================================================================

    private static RetryResult<HttpResponse<String>> sendWithRetry(
            HttpRequest req,
            String type,
            String operation,
            UserRow user,
            String roleName,
            String userNameForSearch,
            String requestBody
    ) {
        int attempt = 0;
        long lastBackoff = 0;
        String retryableReason = "";
        HttpResponse<String> lastResponse = null;
        Exception lastException = null;

        while (attempt < RETRY_MAX_ATTEMPTS) {
            attempt++;
            try {
                lastResponse = HTTP_CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
                int status = lastResponse.statusCode();

                // success
                if (status >= 200 && status < 300) {
                    return new RetryResult<>(lastResponse, attempt, RETRY_MAX_ATTEMPTS, lastBackoff, retryableReason);
                }

                // retryable?
                boolean retryable = (status == 429) || (status >= 500 && status <= 599);
                retryableReason = "httpStatus=" + status;

                if (!retryable || attempt >= RETRY_MAX_ATTEMPTS) {
                    // final failure -> log now
                    logErrorImmediately(new ErrorRecord(
                            nowIsoUtc(),
                            type,
                            operation,
                            attempt,
                            RETRY_MAX_ATTEMPTS,
                            lastBackoff,
                            retryableReason,
                            user != null ? user.umId : null,
                            user != null ? user.userName : userNameForSearch,
                            null,
                            roleName,
                            req.uri().toString(),
                            status,
                            requestBody,
                            lastResponse.body(),
                            "HTTP error"
                    ));
                    return new RetryResult<>(lastResponse, attempt, RETRY_MAX_ATTEMPTS, lastBackoff, retryableReason);
                }

            } catch (Exception e) {
                lastException = e;
                retryableReason = "exception=" + e.getClass().getSimpleName();

                if (attempt >= RETRY_MAX_ATTEMPTS) {
                    logErrorImmediately(new ErrorRecord(
                            nowIsoUtc(),
                            type,
                            operation,
                            attempt,
                            RETRY_MAX_ATTEMPTS,
                            lastBackoff,
                            retryableReason,
                            user != null ? user.umId : null,
                            user != null ? user.userName : userNameForSearch,
                            null,
                            roleName,
                            req.uri().toString(),
                            null,
                            requestBody,
                            null,
                            e.getMessage()
                    ));
                    return new RetryResult<>(null, attempt, RETRY_MAX_ATTEMPTS, lastBackoff, retryableReason);
                }
            }

            // backoff before retry
            lastBackoff = computeBackoffMs(attempt);
            try {
                Thread.sleep(lastBackoff);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                // log and stop
                logErrorImmediately(new ErrorRecord(
                        nowIsoUtc(),
                        type,
                        operation,
                        attempt,
                        RETRY_MAX_ATTEMPTS,
                        lastBackoff,
                        "interrupted",
                        user != null ? user.umId : null,
                        user != null ? user.userName : userNameForSearch,
                        null,
                        roleName,
                        req.uri().toString(),
                        lastResponse != null ? lastResponse.statusCode() : null,
                        requestBody,
                        lastResponse != null ? lastResponse.body() : null,
                        "Interrupted during backoff"
                ));
                return new RetryResult<>(lastResponse, attempt, RETRY_MAX_ATTEMPTS, lastBackoff, "interrupted");
            }
        }

        // Should not reach
        if (lastException != null) {
            logErrorImmediately(new ErrorRecord(
                    nowIsoUtc(),
                    type,
                    operation,
                    attempt,
                    RETRY_MAX_ATTEMPTS,
                    lastBackoff,
                    retryableReason,
                    user != null ? user.umId : null,
                    user != null ? user.userName : userNameForSearch,
                    null,
                    roleName,
                    req.uri().toString(),
                    null,
                    requestBody,
                    null,
                    lastException.getMessage()
            ));
        }
        return new RetryResult<>(lastResponse, attempt, RETRY_MAX_ATTEMPTS, lastBackoff, retryableReason);
    }

    private static long computeBackoffMs(int attempt) {
        // exponential: base * 2^(attempt-1), capped + jitter
        long exp = RETRY_BASE_DELAY_MS * (1L << Math.max(0, attempt - 1));
        long capped = Math.min(exp, RETRY_MAX_DELAY_MS);
        long jitter = (RETRY_JITTER_MS <= 0) ? 0 : new Random().nextLong(RETRY_JITTER_MS + 1);
        return capped + jitter;
    }

    private static synchronized void logErrorImmediately(ErrorRecord r) {
        boolean isUser = "USER".equalsIgnoreCase(r.type);
        Path path = Path.of(isUser ? ERROR_LOG_USER_OUT : ERROR_LOG_GROUP_OUT);

        try (BufferedWriter writer = Files.newBufferedWriter(
                path,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        )) {
            if (isUser && !userErrorHeaderWritten) {
                writer.write(ErrorRecord.header());
                writer.newLine();
                userErrorHeaderWritten = true;
            }
            if (!isUser && !groupErrorHeaderWritten) {
                writer.write(ErrorRecord.header());
                writer.newLine();
                groupErrorHeaderWritten = true;
            }

            writer.write(r.toCsvLine());
            writer.newLine();
            writer.newLine(); // blank line between errors

        } catch (IOException e) {
            System.err.println("❌ Failed to write error immediately: " + e.getMessage());
        }
    }

    private static String nowIsoUtc() {
        return DateTimeFormatter.ISO_INSTANT.format(Instant.now());
    }

    // ===================================================================================
    // Existing users file
    // ===================================================================================

    private static void writeExistingUsersToFile(String filePath) {
        if (existingUsers.isEmpty()) return;

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
        }
    }

    // ===================================================================================
    // Helpers / Models
    // ===================================================================================

    private static String basicAuth() {
        String creds = SCIM_USERNAME + ":" + SCIM_PASSWORD;
        String base64 = Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.UTF_8));
        return "Basic " + base64;
    }

    private static String firstNonNull(String... values) {
        if (values == null) return null;
        for (String v : values) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }

    private static String withUserStoreDomain(String userName) {
        if (userName == null) return null;
        if (userName.contains("/")) return userName;
        return USER_STORE_DOMAIN + "/" + userName;
    }

    private static String withGroupStoreDomain(String roleName) {
        if (roleName == null) return null;
        if (roleName.contains("/")) return roleName;
        return GROUP_STORE_DOMAIN + "/" + roleName;
    }

    private static String safeCsv(String v) {
        if (v == null) return "";
        v = v.replace("\n", " ").replace("\r", " ");
        // keep it simple: wrap if it contains comma or quote
        if (v.contains(",") || v.contains("\"")) {
            v = v.replace("\"", "\"\"");
            return "\"" + v + "\"";
        }
        return v;
    }

    // ===================================================================================
    // Data classes
    // ===================================================================================

    private static class UserRow {
        String umId;
        String userName;
        String password;
        String tenantId;
    }

    private static class RoleRow {
        String umId;
        String roleName;
    }

    private static class UserRoleMapping {
        String umUserId;
        String umRoleId;
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

    private static class RetryResult<T> {
        final T response;
        final int attempt;
        final int maxAttempts;
        final long lastBackoffMs;
        final String retryableReason;

        RetryResult(T response, int attempt, int maxAttempts, long lastBackoffMs, String retryableReason) {
            this.response = response;
            this.attempt = attempt;
            this.maxAttempts = maxAttempts;
            this.lastBackoffMs = lastBackoffMs;
            this.retryableReason = retryableReason;
        }
    }

    private static class ErrorRecord {
        final String timestampIsoUtc;
        final String type;             // USER or GROUP
        final String operation;        // e.g. CREATE_USER
        final int attempt;
        final int maxAttempts;
        final long lastBackoffMs;
        final String retryableReason;

        final String umId;
        final String userName;

        final String roleId;
        final String roleName;

        final String endpoint;
        final Integer httpStatus;
        final String requestBody;
        final String responseBody;
        final String errorMessage;

        ErrorRecord(String timestampIsoUtc,
                    String type,
                    String operation,
                    int attempt,
                    int maxAttempts,
                    long lastBackoffMs,
                    String retryableReason,
                    String umId,
                    String userName,
                    String roleId,
                    String roleName,
                    String endpoint,
                    Integer httpStatus,
                    String requestBody,
                    String responseBody,
                    String errorMessage) {
            this.timestampIsoUtc = timestampIsoUtc;
            this.type = type;
            this.operation = operation;
            this.attempt = attempt;
            this.maxAttempts = maxAttempts;
            this.lastBackoffMs = lastBackoffMs;
            this.retryableReason = retryableReason;
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

        static String header() {
            return String.join(",",
                    "timestampIsoUtc",
                    "type",
                    "operation",
                    "attempt",
                    "maxAttempts",
                    "lastBackoffMs",
                    "retryableReason",
                    "um_id",
                    "userName",
                    "role_id",
                    "roleName",
                    "endpoint",
                    "httpStatus",
                    "requestBody",
                    "responseBody",
                    "errorMessage"
            );
        }

        String toCsvLine() {
            return String.join(",",
                    safeCsv(timestampIsoUtc),
                    safeCsv(type),
                    safeCsv(operation),
                    String.valueOf(attempt),
                    String.valueOf(maxAttempts),
                    String.valueOf(lastBackoffMs),
                    safeCsv(retryableReason),
                    safeCsv(umId),
                    safeCsv(userName),
                    safeCsv(roleId),
                    safeCsv(roleName),
                    safeCsv(endpoint),
                    httpStatus == null ? "" : String.valueOf(httpStatus),
                    safeCsv(requestBody),
                    safeCsv(responseBody),
                    safeCsv(errorMessage)
            );
        }
    }
}
