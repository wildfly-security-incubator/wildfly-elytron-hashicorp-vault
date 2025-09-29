/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import static org.wildfly.security.hashicorp.vault.VaultTestUtils.startVaultTestContainer;

public class VaultCredentialStoreTestCase {

    private VaultContainer<?> vaultTestContainer;

    @After
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }


    @Test
    public void testCredentialStoreRetrieve() throws Exception {

        vaultTestContainer = VaultTestUtils.startVaultTestContainer();
        VaultCredentialStore cs = new VaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        cs.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        PasswordCredential credential = cs.retrieve("secret/testing1.top_secret", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, null);
        Assert.assertEquals("password123", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    @Test
    public void testCredentialStorePut() throws Exception {
        VaultCredentialStore vaultCredentialStore;
        Map<String, String> attributes;
        vaultTestContainer = startVaultTestContainer();
        vaultCredentialStore = new VaultCredentialStore();
        attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        vaultCredentialStore.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        vaultCredentialStore.store("secret/testing1.test_secret", createCredentialFromPassword("testPassword"), null);
        PasswordCredential credential = vaultCredentialStore
                .retrieve("secret/testing1.test_secret", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null,
                        new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))));
        Assert.assertEquals("testPassword", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    private PasswordCredential createCredentialFromPassword(String password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, WildFlyElytronPasswordProvider.getInstance());
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }
}
