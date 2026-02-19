/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.jboss.logging.Logger;
import org.wildfly.security.hashicorp.vault.loginstrategy.ClientCertificateLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.JwtLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.LoginContext;
import org.wildfly.security.hashicorp.vault.loginstrategy.TokenLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.VaultLoginStrategy;

import javax.net.ssl.SSLContext;

/**
 * Vault Connector
 */
public class VaultConnector {

    private static final Logger logger = Logger.getLogger(VaultConnector.class);

    private final String vaultUrl;
    private final String token;
    private final String namespace;
    private final SslConfig sslConfig;
    private Vault vault;
    private final SSLContext sslContext;

    private JwtConfig jwtConfig;

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify) {
        this(vaultUrl, token, namespace, sslConfig, sslVerify, null);
    }

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify, SSLContext sslContext) {
        this.vaultUrl = vaultUrl;
        this.token = token;
        this.namespace = namespace;
        this.sslConfig = sslConfig;
        this.sslContext = sslContext;
    }

    public VaultConnector(String vaultUrl, JwtConfig jwtConfig, String namespace, SslConfig sslConfig) {
        this(vaultUrl, jwtConfig, namespace, sslConfig, null);
    }

    public VaultConnector(String vaultUrl, JwtConfig jwtConfig, String namespace, SslConfig sslConfig, SSLContext sslContext) {
        this.vaultUrl = vaultUrl;
        this.token = null;
        this.namespace = namespace;
        this.sslConfig = sslConfig;
        this.jwtConfig = jwtConfig;
        this.sslContext = sslContext;
    }

    public void configure() throws VaultException {
        try {

            VaultConfig config = new VaultConfig()
                    .sslConfig(this.sslConfig)
                    .address(this.vaultUrl);
            HttpClient httpClient;

            if (sslContext != null) {
                httpClient = HttpClient.newBuilder()
                        .sslContext(sslContext)
                        .build();
                config.httpClient(httpClient);
            }

            if (this.namespace != null && !this.namespace.isEmpty()) {
                config.nameSpace(this.namespace);
            }

            final LoginContext loginContext = new LoginContext(token, jwtConfig,
                    Vault.create(config.build()));
            this.vault = tryLoginWithFallback(loginContext, config);

            logger.debugf("Vault configuration successful for URL: %s", this.vaultUrl);
        } catch (VaultException e) {
            logger.errorf("Failed to configure Vault connection to %s: %s", this.vaultUrl, e.getMessage());
            throw e;
        }
    }

    /**
     * Login with subsequently with each possible method and stop when login was successful. Resulting Vault will carry
     * VaultConfig with token which obtained from the final login attempt.
     * Note that only methods which prerequisites are satisfied will be tried.
     * @param loginContext current login context
     * @param config initial VaultConfig
     * @return Vault with token configured
     * @throws VaultException thrown when anything goes wrong, including situation when all methods fail.
     */
    private Vault tryLoginWithFallback(LoginContext loginContext, VaultConfig config) throws VaultException {
        for (VaultLoginStrategy strategy : composePossibleLoginStrategiesPrioritized(loginContext, config.getSslConfig())) {
            try {
                String response = strategy.tryLogin(loginContext);

                if (response != null) {
                    config.token(response);
                    Vault vault = Vault.create(config.build());
                    //test that token can be used to perform anything requiring authentication
                    vault.auth().lookupSelf();
                    return vault;
                }
            } catch (VaultException e) {
                logger.debugf(e, "Unable to login with %s", strategy.getClass().getSimpleName());
            }
        }

        throw new VaultException("All login strategies failed");
    }

    private List<VaultLoginStrategy> composePossibleLoginStrategiesPrioritized(final LoginContext loginContext,
                                                                               final SslConfig sslConfig) {
        final List<VaultLoginStrategy> loginStrategies = new ArrayList<>();
        if (sslConfig != null) {
            loginStrategies.add(new ClientCertificateLoginStrategy());
        }
        if (loginContext.getJwtConfig() != null) {
            loginStrategies.add(new JwtLoginStrategy());
        }
        if (loginContext.getToken() != null) {
            loginStrategies.add(new TokenLoginStrategy());
        }
        return loginStrategies;
    }

    /**
     * Retrieve a secret from Vault
     */
    public String getSecret(String path, String key) throws VaultException {
        if (path == null || path.trim().isEmpty()) {
            throw new VaultException("Path cannot be null or empty");
        }
        if (key == null || key.trim().isEmpty()) {
            throw new VaultException("Key cannot be null or empty");
        }

        // Fetch from Vault
        LogicalResponse response = this.vault.logical().read(path);
        int responseStatus = response.getRestResponse().getStatus();
        if (responseStatus == 200) {
            Map<String, String> data = response.getData();
            String value = data.get(key);
            if (value != null) {
                logger.tracef("Vault retrieved secret successfully from path: %s, url: %s", path, this.vaultUrl);
            } else {
                logger.tracef("Key '%s' not found in secret at path: %s", key, path);
            }
            return value;
        }
        if (responseStatus == 403) {
            logger.tracef("Forbidden to retrieve the secret from vault at path: %s", path);
            throw new VaultException("Forbidden to retrieve secret at path: " + path);
        }
        if (responseStatus == 404) {
            logger.tracef("Secret not found at path: %s", path);
            return null;
        }

        throw new VaultException("Failed to retrieve secret from path: " + path + "/" + key + " (HTTP " + responseStatus + ")");
    }

    /**
     * Store a secret in Vault
     */
    public void putSecret(String path, String key, String value) throws VaultException {
        if (path == null || path.trim().isEmpty()) {
            throw new VaultException("Path cannot be null or empty");
        }
        if (key == null || key.trim().isEmpty()) {
            throw new VaultException("Key cannot be null or empty");
        }
        if (value == null) {
            throw new VaultException("Value cannot be null");
        }

        Map<String, Object> nameValuePairs = new HashMap<>();
        // Read existing path to preserve other keys if those exist
        LogicalResponse readResponse = this.vault.logical().read(path);
        int readStatus = readResponse.getRestResponse().getStatus();
        if (readStatus == 200) {
            Map<String, String> existingData = readResponse.getData();
            if (existingData != null) {
                nameValuePairs.putAll(existingData);
            }
        }

        nameValuePairs.put(key, value);
        LogicalResponse response = this.vault.logical().write(path, nameValuePairs);
        int responseStatus = response.getRestResponse().getStatus();
        if (responseStatus == 200 || responseStatus == 204) {
            logger.tracef("Vault stored secret successfully at path: %s, url: %s", path, this.vaultUrl);
            return;
        }
        if (responseStatus == 403) {
            throw new VaultException("Forbidden to store secret at path: " + path);
        }

        throw new VaultException("Failed to store secret at path: " + path + "/" + key + " (HTTP " + responseStatus + ")");
    }

    /**
     * Remove a secret from Vault
     */
    public void removeSecret(String path, String key) throws VaultException {
        if (path == null || path.trim().isEmpty()) {
            throw new VaultException("Path cannot be null or empty");
        }
        if (key == null || key.trim().isEmpty()) {
            throw new VaultException("Key cannot be null or empty");
        }

        // Read existing path to preserve other keys at the same path
        Map<String, Object> nameValuePairs = new HashMap<>();
        LogicalResponse readResponse = this.vault.logical().read(path);
        int readStatus = readResponse.getRestResponse().getStatus();
        if (readStatus == 200) {
            Map<String, String> existingData = readResponse.getData();
            if (existingData != null) {
                nameValuePairs.putAll(existingData);
            }
        }

        if (!nameValuePairs.containsKey(key)) {
            logger.tracef("Key %s does not exist at path %s", key, path);
            return;
        }
        nameValuePairs.remove(key);
        if (nameValuePairs.isEmpty()) {
            LogicalResponse deleteResponse = this.vault.logical().delete(path);
            int deleteStatus = deleteResponse.getRestResponse().getStatus();
            if (deleteStatus == 200 || deleteStatus == 204) {
                logger.tracef("Vault deleted secret path successfully (no keys remaining): %s", path);
                return;
            }
            if (deleteStatus == 403) {
                throw new VaultException("Forbidden to delete secret at path: " + path);
            }
            throw new VaultException("Failed to delete secret at path: " + path + " (HTTP " + deleteStatus + ")");
        } else {
            // Write back the remaining keys
            LogicalResponse writeResponse = this.vault.logical().write(path, nameValuePairs);
            int writeStatus = writeResponse.getRestResponse().getStatus();
            if (writeStatus == 200 || writeStatus == 204) {
                logger.tracef("Vault removed key %s from path %s successfully", key, path);
                return;
            }
            if (writeStatus == 403) {
                throw new VaultException("Forbidden to update secret at path: " + path);
            }
            throw new VaultException("Failed to update secret at path: " + path + " after removing key " + key + " (HTTP " + writeStatus + ")");
        }
    }

    /**
     * Get all keys for a specific path
     */
    public Set<String> getKeysForPath(String path) throws VaultException {
        LogicalResponse response = this.vault.logical().read(path);
        int responseStatus = response.getRestResponse().getStatus();
        if (responseStatus == 200) {
            Map<String, String> data = response.getData();
            if (data != null && !data.isEmpty()) {
                return new HashSet<>(data.keySet());
            }
            return new HashSet<>();
        } else if (responseStatus == 404) {
            throw new VaultException("Path does not exist or forbidden: \"" + path + "\"");
        } else {
            throw new VaultException("Failed to read aliases on path: \"" + path + "\"");
        }
    }

    /**
     * Get a set of all items at a given path (without the parent path prefix)
     */
    public Set<String> listAllItemsAtPath(String path) throws VaultException {
        if (path == null || path.trim().isEmpty()) {
            throw new VaultException("Path cannot be null or empty");
        }
        // vault expects trailing slash with list operation
        String listPath = path.endsWith("/") ? path : path + "/";
        
        try {
            LogicalResponse response = this.vault.logical().list(listPath);
            int responseStatus = response.getRestResponse().getStatus();
            if (responseStatus == 200) {
                List<String> keys = response.getListData();
                if (keys != null && !keys.isEmpty()) {
                    return new HashSet<>(keys);
                }
                return new HashSet<>();
            } else if (responseStatus == 404) {
                throw new VaultException("Path not found in vault: \"" + path + "\"");
            } else if (responseStatus == 403) {
                throw new VaultException("Forbidden to list subpaths at path: \"" + path + "\"");
            } else {
                throw new VaultException("Failed to list subpaths at path: \"" + path + "\" (HTTP " + responseStatus + ")");
            }
        } catch (ClassCastException e) {
            throw new VaultException("Unexpected response format when listing subpaths at path: \"" + path + "\": " + e.getMessage());
        }
    }
}
