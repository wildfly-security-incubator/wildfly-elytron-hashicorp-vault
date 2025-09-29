/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.util.HashMap;
import java.util.Map;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.jboss.logging.Logger;

/**
 * Vault Connector
 */
public class VaultConnector {

    private static final Logger logger = Logger.getLogger(VaultConnector.class);

    private final String vaultUrl;
    private final String token;
    private final String namespace;
    private final boolean sslVerify;
    private final SslConfig sslConfig;
    private Vault vault;

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify) {
        this.vaultUrl = vaultUrl;
        this.token = token;
        this.namespace = namespace;
        this.sslVerify = sslVerify;
        this.sslConfig = sslConfig;
    }

    public void configure() throws VaultException {
        try {
            VaultConfig config = new VaultConfig()
                    .sslConfig(this.sslConfig)
                    .address(this.vaultUrl)
                    .token(this.token);
            SslConfig sslConfig = config.getSslConfig();

            if (sslConfig != null) {
                sslConfig.verify(this.sslVerify);
            }

            if (this.namespace != null && !this.namespace.isEmpty()) {
                config.nameSpace(this.namespace);
            }

            this.vault = Vault.create(config);

            // Test connection to validate configuration
            this.vault.auth().lookupSelf();
            logger.debugf("Vault configuration successful for URL: %s", this.vaultUrl);
        } catch (VaultException e) {
            logger.errorf("Failed to configure Vault connection to %s: %s", this.vaultUrl, e.getMessage());
            throw new VaultException("Failed to configure Vault connection: " + e.getMessage());
        }
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
            throw new VaultException("Secret not found at path: " + path);
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
        nameValuePairs.put(key, value);
        LogicalResponse response = this.vault.logical().write(path, nameValuePairs);
        int responseStatus = response.getRestResponse().getStatus();
        if (responseStatus == 200 || responseStatus == 204) {
            logger.tracef("Vault stored secret successfully at path: %s, url: %s", path, this.vaultUrl);
            return;
        }
        if (responseStatus == 403) {
            logger.tracef("Forbidden to store the secret in vault at path: %s", path);
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

        LogicalResponse response = this.vault.logical().delete(path);
        int responseStatus = response.getRestResponse().getStatus();
        if (responseStatus == 200 || responseStatus == 204) {
            logger.tracef("Vault deleted secret successfully at path: %s, url: %s", path, this.vaultUrl);
            return;
        }
        if (responseStatus == 403) {
            logger.tracef("Forbidden to delete secret from vault at path: %s", path);
            throw new VaultException("Forbidden to delete secret at path: " + path);
        }

        logger.tracef("Failed to delete secret, response status: %d", responseStatus);
        throw new VaultException("Failed to delete secret at path: " + path + "/" + key + " (HTTP " + responseStatus + ")");
    }
}
