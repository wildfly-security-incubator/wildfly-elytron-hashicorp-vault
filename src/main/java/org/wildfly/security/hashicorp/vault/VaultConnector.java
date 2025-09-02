/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.jboss.logging.Logger;

/**
 * Service for vault
 */
public class VaultConnector {

    private static final Logger logger = Logger.getLogger(VaultConnector.class);

    private final String vaultUrl;
    private final String token;
    private final String namespace;
    private final boolean sslVerify;
    private final SslConfig sslConfig;

    private Vault vault;
    private final Map<String, Object> secretCache = new ConcurrentHashMap<>();

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify) {
        this.vaultUrl = vaultUrl;
        this.token = token;
        this.namespace = namespace;
        this.sslVerify = sslVerify;
        this.sslConfig = sslConfig;
    }

    public void configure() {
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

            // Test connection
            // his.vault.auth().lookupSelf();
        } catch (VaultException ignored) {

        }
    }


    /**
     * Retrieve a secret from Vault
     */
    public String getSecret(String path, String key) throws VaultException {
        String cacheKey = path + ":" + key;

        // Check cache first
        Object cachedValue = this.secretCache.get(cacheKey);
        if (cachedValue != null) {
            return (String) cachedValue;
        }

        // Fetch from Vault
        LogicalResponse response = this.vault.logical().read(path);
        int responseStatus = response.getRestResponse().getStatus();
        if (responseStatus == 200) {
            Map<String, String> data = response.getData();
            String value = data.get(key);

            // Cache the value
            if (value != null) {
                this.secretCache.put(cacheKey, value);
            }

            logger.tracef("Vault retrieved secret successfully, url: %s", this.vaultUrl);
            return value;
        }
        if (responseStatus == 403) {
            logger.tracef("Forbidden to retrieve the secret from vault");
            throw new VaultException("Forbidden");
        }

        throw new VaultException("Secret not found: " + path + "/" + key);
    }
}
