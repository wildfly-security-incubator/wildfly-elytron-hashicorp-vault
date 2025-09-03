package org.wildfly.security.hashicorp.vault;

import io.github.jopenlibs.vault.SslConfig;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.interfaces.ClearPassword;

import java.io.IOException;
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

    @Override
    public void initialize(Map<String, String> attributes, CredentialStore.ProtectionParameter protectionParameter, Provider[] providers) throws CredentialStoreException {
        // check the connection to the vault
        this.hostAddress = attributes.get("host-address");
        this.namespace = attributes.get("namespace");
        this.protectionParameter = protectionParameter;
        VaultConnector vaultConnector;
        try {
            vaultConnector = new VaultConnector(attributes.get("host-address"), String.valueOf(getStorePassword(protectionParameter)), attributes.get("namespace"), new SslConfig().verify(false), false);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        vaultConnector.configure();

        initialized = true;
        // no operation
    }

    @Override
    public boolean isModifiable() {
        return true;
    }

    @Override
    public void store(String credentialAlias, Credential credential, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException, UnsupportedCredentialTypeException {
        // invoke the CredentialSource to store new credential of type clear text for now
    }

    @Override
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {

        VaultConnector vaultConnector = null;
        try {
            vaultConnector = new VaultConnector(this.hostAddress, String.valueOf(getStorePassword(this.protectionParameter)), this.namespace, new SslConfig().verify(false), false);
        } catch (IOException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
        // process credentialAlias to obtain secret path and key/name
        String[] aliasSplit = credentialAlias.split("\\.");
        PasswordCredential credential;
        CredentialSource cs = new VaultCredentialSource(vaultConnector, aliasSplit[0], aliasSplit[1]);
        try {
            credential = cs.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return credentialType.cast(credential);
    }

    @Override
    public void remove(String credentialAlias, Class<? extends Credential> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {

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
