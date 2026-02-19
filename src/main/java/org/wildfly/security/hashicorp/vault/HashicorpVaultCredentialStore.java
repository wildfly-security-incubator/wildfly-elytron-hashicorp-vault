/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.interfaces.ClearPassword;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.wildfly.security.credential.store._private.ElytronMessages.log;

/**
 * Credential store backed by Hashicorp Vault
 */
public class HashicorpVaultCredentialStore extends CredentialStoreSpi {

    private static final int DEFAULT_MAX_ALIASES = 10_000;
    private static final int DEFAULT_MAX_DEPTH = 100;
    /** Default maximum number of credentials to keep in the in-memory cache. */
    private static final int DEFAULT_CREDENTIAL_CACHE_MAX_SIZE = 500;

    String hostAddress;
    String namespace;
    CredentialStore.ProtectionParameter protectionParameter;
    Provider[] providers;
    VaultConnector vaultConnector;
    private String trustStorePath;
    private String keyStorePath;
    private String keyStorePass;
    private String trustStorePass;

    /** In-memory LRU cache of retrieved credentials, keyed by credential alias (e.g. "path.key"). */
    private Map<String, Credential> credentialCache;

    @Override
    public void initialize(Map<String, String> attributes, CredentialStore.ProtectionParameter protectionParameter, Provider[] providers) throws CredentialStoreException {
        if (attributes == null) {
            throw new CredentialStoreException("Attributes cannot be null");
        }
        
        // Check required attributes
        this.hostAddress = attributes.get("host-address");
        if (this.hostAddress == null || this.hostAddress.trim().isEmpty()) {
            throw new CredentialStoreException("host-address attribute is required");
        }

        if (attributes.get("trust-store-path") != null) {
            this.trustStorePath = attributes.get("trust-store-path");
        }

        if (attributes.get("key-store-path") != null) {
            this.keyStorePath = attributes.get("key-store-path");
        }

        if (attributes.get("key-store-pass") != null) {
            this.keyStorePass = attributes.get("key-store-pass");
        }

        if (attributes.get("trust-store-pass") != null) {
            this.trustStorePass = attributes.get("trust-store-pass");
        }
        
        this.namespace = attributes.get("namespace");
        this.protectionParameter = protectionParameter;
        this.providers = providers;

        this.credentialCache = Collections.synchronizedMap(new LinkedHashMap<String, Credential>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Credential> eldest) {
                return size() > DEFAULT_CREDENTIAL_CACHE_MAX_SIZE;
            }
        });

        try {
            char[] password = getStorePassword(protectionParameter);
            String token = password != null ? String.valueOf(password) : null;
            if (token == null) {
                throw new CredentialStoreException("Vault token is required");
            }
            
            SslConfig sslConfig = new SslConfig().verify(true);
            
            if (this.keyStorePath != null && !this.keyStorePath.trim().isEmpty()) {
                try {
                    KeyStore keyStore = KeyStore.getInstance("JKS");
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(this.keyStorePath)) {
                        keyStore.load(fis, this.keyStorePass != null ? this.keyStorePass.toCharArray() : null);
                    }
                    
                    if (this.keyStorePass != null) {
                        sslConfig.keyStore(keyStore, this.keyStorePass);
                    } else {
                        sslConfig.keyStore(keyStore, "");
                    }
                } catch (Exception e) {
                    throw new CredentialStoreException("Failed to load KeyStore from path: " + e.getMessage(), e);
                }
            }
            
            if (this.trustStorePath != null && !this.trustStorePath.trim().isEmpty()) {
                try {
                    KeyStore trustStore = KeyStore.getInstance("JKS");
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(this.trustStorePath)) {
                        trustStore.load(fis, this.trustStorePass != null ? this.trustStorePass.toCharArray() : null);
                    }
                    if (this.trustStorePass != null) {
                        sslConfig.trustStore(trustStore);
                    } else {
                        sslConfig.trustStore(trustStore);
                    }
                } catch (Exception e) {
                    throw new CredentialStoreException("Failed to load TrustStore from path: " + e.getMessage(), e);
                }
            }

            vaultConnector = new VaultConnector(this.hostAddress, token, this.namespace, sslConfig, true);
            vaultConnector.configure();
            
            initialized = true;
        } catch (IOException e) {
            throw new CredentialStoreException("Failed to initialize vault credential store", e);
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to configure vault connection", e);
        }
    }

    @Override
    public boolean isModifiable() {
        return true;
    }

    @Override
    public void store(String credentialAlias, Credential credential, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException, UnsupportedCredentialTypeException {
        if (!initialized) {
            throw new CredentialStoreException("Credential store is not initialized");
        }
        if (credentialAlias == null || credentialAlias.trim().isEmpty()) {
            throw new CredentialStoreException("Credential alias has to be provided");
        }
        if (credential == null) {
            throw new CredentialStoreException("Credential cannot be null");
        }
        
        // Parse credentialAlias in format "path.key"
        String[] aliasSplit = credentialAlias.split("\\.");
        if (aliasSplit.length != 2) {
            throw new CredentialStoreException("Credential alias must be in format 'path.key', got: " + credentialAlias);
        }
        
        try {
            final char[] chars = credential.castAndApply(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
            if (chars == null) {
                throw new CredentialStoreException("Failed to extract password from credential");
            }
            vaultConnector.putSecret(aliasSplit[0], aliasSplit[1], new String(chars));
            putInCredentialCache(credentialAlias, credential);
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to store credential in vault", e);
        } catch (ClassCastException e) {
            throw new UnsupportedCredentialTypeException("Only PasswordCredential with ClearPassword is supported", e);
        }
    }

    @Override
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        if (!initialized) {
            throw new CredentialStoreException("Credential store is not initialized");
        }
        if (credentialAlias == null || credentialAlias.trim().isEmpty()) {
            throw new CredentialStoreException("Credential alias has to be provided");
        }
        
        // Parse credentialAlias in format "path.key"
        String[] aliasSplit = credentialAlias.split("\\.");
        if (aliasSplit.length != 2) {
            throw new CredentialStoreException("Credential alias must be in format 'path.key', got: " + credentialAlias);
        }

        Credential cached;
        synchronized (credentialCache) {
            cached = credentialCache.get(credentialAlias);
        }
        if (credentialType.isInstance(cached)) {
            return credentialType.cast(cached);
        }
        
        try {
            CredentialSource credentialSource = new VaultCredentialSource(vaultConnector, aliasSplit[0], aliasSplit[1]);
            PasswordCredential credential = credentialSource.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
            if (credential == null) {
                return null; // Secret not found or key not found in secret
            }
            putInCredentialCache(credentialAlias, credential);
            return credentialType.cast(credential);
        } catch (IOException e) {
            throw new CredentialStoreException("Failed to retrieve credential from vault", e);
        } catch (ClassCastException e) {
            throw new CredentialStoreException("Requested credential type is not supported: " + credentialType.getSimpleName(), e);
        }
    }

    @Override
    public void remove(String credentialAlias, Class<? extends Credential> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        if (!initialized) {
            throw new CredentialStoreException("Credential store is not initialized");
        }
        if (credentialAlias == null || credentialAlias.trim().isEmpty()) {
            throw new CredentialStoreException("Credential alias has to be provided");
        }
        
        // Parse credentialAlias in format "path.key"
        String[] aliasSplit = credentialAlias.split("\\.");
        if (aliasSplit.length != 2) {
            throw new CredentialStoreException("Credential alias must be in format 'path.key', got: " + credentialAlias);
        }
        
        try {
            vaultConnector.removeSecret(aliasSplit[0], aliasSplit[1]);
            synchronized (credentialCache) {
                // we need to remove whole path because that is how the vault's removeSecret operation works
                credentialCache.keySet().removeIf(k -> k.equals(credentialAlias) || k.startsWith(aliasSplit[0] + "."));
            }
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to remove credential from vault", e);
        }
    }

    private void putInCredentialCache(String alias, Credential credential) {
        synchronized (credentialCache) {
            credentialCache.put(alias, credential);
        }
    }

    private static char[] getStorePassword(final CredentialStore.ProtectionParameter protectionParameter) throws IOException, CredentialStoreException {
        final char[] password;
        if (protectionParameter instanceof CredentialStore.CredentialSourceProtectionParameter) {
            password = ((CredentialStore.CredentialSourceProtectionParameter) protectionParameter).
                    getCredentialSource()
                    .applyToCredential(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        } else if (protectionParameter != null) {
            throw log.invalidProtectionParameter(protectionParameter);
        } else {
            password = null;
        }
        return password;
    }

    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        // Use "secret/" as the default path when none provided
        return getAliases("secret/");
    }

    /**
     * Get aliases from a specific path in Vault.
     *
     * @param path the Vault path to start listing from (e.g., "secret"). If null or empty, throw exception
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path) throws CredentialStoreException {
        if (!initialized) {
            throw new CredentialStoreException("Credential store is not initialized");
        }
        if (path == null || path.trim().isEmpty()) {
            throw new CredentialStoreException("Empty or null path provided to getAliases operation");
        }
        return collectAliases(normalizePath(path), false, 0);
    }

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal.
     *
     * @param path the Vault path to start listing from. If null or empty, throw exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path, boolean recursive) throws CredentialStoreException {
        if (!initialized) {
            throw new CredentialStoreException("Credential store is not initialized");
        }
        if (path == null || path.trim().isEmpty()) {
            throw new CredentialStoreException("Empty or null path provided to getAliases operation");
        }
        return collectAliases(normalizePath(path), recursive, DEFAULT_MAX_DEPTH);
    }

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal.
     *
     * @param path the Vault path to start listing from. If null or empty, throw exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @param recursiveDepth the maximum depth to traverse if recursive is true. 0 means only the specified path,
     *                       1 means one level deep, etc. Ignored if recursive is false.
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path, boolean recursive, int recursiveDepth) throws CredentialStoreException {
        if (!initialized) {
            throw new CredentialStoreException("Credential store is not initialized");
        }
        if (path == null || path.trim().isEmpty()) {
            throw new CredentialStoreException("Empty or null path provided to getAliases operation");
        }
        if (recursiveDepth < 0) {
            throw new CredentialStoreException("recursive-depth must be non-negative, got: " + recursiveDepth);
        }
        return collectAliases(normalizePath(path), recursive, recursiveDepth);
    }

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal and maximum alias limit.
     *
     * @param path the Vault path to start listing from (e.g., "secret"). If null or empty, throw exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @param recursiveDepth the maximum depth to traverse if recursive is true. 0 means only the specified path,
     *                       1 means one level deep, etc. Ignored if recursive is false.
     * @param maxNumberOfAliases the maximum number of aliases to return. Must be positive. Collection stops when this limit is reached.
     * @return set of aliases in format "path.key", containing at most maxNumberOfAliases aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path, boolean recursive, int recursiveDepth, int maxNumberOfAliases) throws CredentialStoreException {
        if (!initialized) {
            throw new CredentialStoreException("Credential store is not initialized");
        }
        if (path == null || path.trim().isEmpty()) {
            throw new CredentialStoreException("Empty or null path provided to getAliases operation");
        }
        if (recursiveDepth < 0) {
            throw new CredentialStoreException("recursive-depth must be non-negative, got: " + recursiveDepth);
        }
        if (maxNumberOfAliases <= 0) {
            throw new CredentialStoreException("maxNumberOfAliases must be positive, got: " + maxNumberOfAliases);
        }
        return collectAliases(normalizePath(path), recursive, recursiveDepth, maxNumberOfAliases);
    }

    private Set<String> collectAliases(String path, boolean recursive, int maxDepth) throws CredentialStoreException {
        return collectAliases(path, recursive, maxDepth, DEFAULT_MAX_ALIASES);
    }

    private Set<String> collectAliases(String path, boolean recursive, int maxDepth, int maxNumberOfAliases) throws CredentialStoreException {
        Set<String> aliases = new HashSet<>();
        collectAliasesRecursive(path, aliases, recursive, maxDepth, 0, maxNumberOfAliases);
        return aliases;
    }

    // Keep an eye on https://github.com/hashicorp/vault/issues/5275 and remove this logic once hashicorp vault provides this operation
    private void collectAliasesRecursive(String path, Set<String> aliases, boolean recursive, int maxDepth, int currentDepth, int maxNumberOfAliases) throws CredentialStoreException {
        if (aliases.size() >= maxNumberOfAliases) {
            return;
        }

        try {
            Set<String> keys = vaultConnector.getKeysForPath(path);
            for (String key : keys) {
                if (aliases.size() >= maxNumberOfAliases) {
                    return;
                }
                aliases.add(path + "." + key);
            }
        } catch (VaultException e) {
            if (e.getMessage().contains("Path does not exist")) {
                // ignore because this path in the tree can be empty, but other paths not so continue traversal
            } else {
                throw new CredentialStoreException("Could not read keys from path \"" + path + "\" (currentDepth=" + currentDepth + ", recursive=" + recursive + "), message is: " + e.getMessage(), e);
            }
        }

        if (recursive && currentDepth < maxDepth && aliases.size() < maxNumberOfAliases) {
            try {
                Set<String> items = vaultConnector.listAllItemsAtPath(path);
                if (items.isEmpty()) {
                    return;
                }
                for (String item : items) {
                    if (aliases.size() >= maxNumberOfAliases) {
                        return;
                    }
                    String fullItemPath = normalizePath(path) + "/" + item;
                    boolean isSubpath = item.endsWith("/");
                    if (!isSubpath) {
                        try {
                            Set<String> keys = vaultConnector.getKeysForPath(fullItemPath);
                            for (String key : keys) {
                                if (aliases.size() >= maxNumberOfAliases) {
                                    return;
                                }
                                aliases.add(fullItemPath + "." + key);
                            }
                        } catch (VaultException e) {
                            // Path doesn't have keys or doesn't exist - continue with other paths
                        }
                    } else {
                        collectAliasesRecursive(fullItemPath, aliases, recursive, maxDepth, currentDepth + 1, maxNumberOfAliases);
                    }
                }
            } catch (VaultException e) {
                String errorMsg = e.getMessage();
                if (errorMsg != null && errorMsg.contains("403")) {
                    throw new CredentialStoreException("Forbidden to list subpaths at path \"" + path + "\"", e);
                }
            }
        }
    }

    private String normalizePath(String path) {
        return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }
}
