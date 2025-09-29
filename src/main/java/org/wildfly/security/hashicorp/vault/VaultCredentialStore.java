/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;
import io.restassured.config.SSLConfig;
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
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;

import static org.wildfly.security.credential.store._private.ElytronMessages.log;

/**
 * Credential store backed by Hashicorp Vault
 */
public class VaultCredentialStore extends CredentialStoreSpi {

    String hostAddress;
    String namespace;
    CredentialStore.ProtectionParameter protectionParameter;
    Provider[] providers;
    VaultConnector vaultConnector;
    private String trustStorePath;
    private String keyStorePath;
    private String keyStorePass;

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

        if (attributes.get("trustStorePath") != null) {
            this.trustStorePath = attributes.get("trustStorePath");
        }

        if (attributes.get("keyStorePath") != null) {
            this.keyStorePath = attributes.get("keyStorePath");
        }

        if (attributes.get("keyStorePass") != null) {
            this.keyStorePass = attributes.get("keyStorePass");
        }
        
        this.namespace = attributes.get("namespace");
        this.protectionParameter = protectionParameter;
        this.providers = providers;
        
        try {
            char[] password = getStorePassword(protectionParameter);
            String token = password != null ? String.valueOf(password) : null;
            if (token == null) {
                throw new CredentialStoreException("Vault token is required");
            }

            SslConfig sslConfig = new SslConfig()
                    .trustStore(KeyStore.getInstance(trustStorePath))
                    .keyStore(KeyStore.getInstance(keyStorePath), keyStorePass);
            vaultConnector = new VaultConnector(this.hostAddress, token, this.namespace, sslConfig, true);
            vaultConnector.configure();
            
            initialized = true;
        } catch (IOException e) {
            throw new CredentialStoreException("Failed to initialize vault credential store", e);
        } catch (VaultException | KeyStoreException e) {
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
        
        try {
            CredentialSource credentialSource = new VaultCredentialSource(vaultConnector, aliasSplit[0], aliasSplit[1]);
            PasswordCredential credential = credentialSource.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
            if (credential == null) {
                return null; // Secret not found or key not found in secret
            }
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
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to remove credential from vault", e);
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
}
