/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
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
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.security.hashicorp.vault.VaultTestUtils.startVaultTestContainer;

public class HashicorpVaultCredentialStoreTestCase {

    private VaultContainer<?> vaultTestContainer;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }


    @Test
    public void testCredentialStoreRetrieve() throws Exception {

        vaultTestContainer = VaultTestUtils.startVaultTestContainer();
        HashicorpVaultCredentialStore cs = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        cs.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        PasswordCredential credential = cs.retrieve("secret/testing1.top_secret", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, null);
        assertEquals("password123", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    @Test
    public void testCredentialStorePut() throws Exception {
        HashicorpVaultCredentialStore hashicorpVaultCredentialStore;
        Map<String, String> attributes;
        vaultTestContainer = startVaultTestContainer();
        hashicorpVaultCredentialStore = new HashicorpVaultCredentialStore();
        attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        hashicorpVaultCredentialStore.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        hashicorpVaultCredentialStore.store("secret/testing1.test_secret", createCredentialFromPassword("testPassword"), null);
        PasswordCredential credential = hashicorpVaultCredentialStore
                .retrieve("secret/testing1.test_secret", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null,
                        new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))));
        assertEquals("testPassword", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    @Test
    public void testPutMaintainsExistingKeys() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        store.store("secret/myapp.mp", createCredentialFromPassword("password1"), null);
        store.store("secret/myapp.mp2", createCredentialFromPassword("password2"), null);
        PasswordCredential credential1 = store.retrieve("secret/myapp.mp", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, createProtectionParameter("myroot"));
        assertNotNull(credential1);
        PasswordCredential credential2 = store.retrieve("secret/myapp.mp2", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, createProtectionParameter("myroot"));
        assertNotNull(credential2);
    }

    @Test
    public void testRemoveKeepsOtherKeys() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        store.store("secret/myapp.mp", createCredentialFromPassword("password1"), null);
        store.store("secret/myapp.mp2", createCredentialFromPassword("password2"), null);
        store.remove("secret/myapp.mp2", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        PasswordCredential remaining = store.retrieve("secret/myapp.mp", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, createProtectionParameter("myroot"));
        assertNotNull(remaining);
        assertEquals("password1", String.valueOf(remaining.getPassword(ClearPassword.class).getPassword()));
        PasswordCredential removed = store.retrieve("secret/myapp.mp2", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, createProtectionParameter("myroot"));
        assertNull(removed);
    }

    /**
     * Read aliases from a specific vault path that contains secrets.
     * Test that only the aliases stored at specific path are returned, none from the other path
     */
    @Test
    public void testGetAliasesWithPath() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        cs.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        Set<String> aliases = cs.getAliases("secret/testing1");
        assertNotNull(aliases);
        assertFalse(aliases.isEmpty());
        assertTrue(aliases.contains("secret/testing1.top_secret"));
        assertFalse(aliases.contains("secret/testing2.dbuser"));
        assertFalse(aliases.contains("secret/testing2.jmsuser"));

        aliases = cs.getAliases("secret/testing2");
        assertNotNull(aliases);
        assertFalse(aliases.isEmpty());
        assertTrue(aliases.contains("secret/testing2.dbuser"));
        assertTrue(aliases.contains("secret/testing2.jmsuser"));
        assertFalse(aliases.contains("secret/testing1.top_secret"));
    }

    /**
     * The call must throw a {@link CredentialStoreException} when null path is provided
     */
    @Test
    public void testGetAliasesWithNullPath() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        cs.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        assertThrows(CredentialStoreException.class, () -> cs.getAliases((String) null));
    }

    /**
     * The call must throw a {@link CredentialStoreException} when empty path is provided
     */
    @Test
    public void testGetAliasesWithEmptyPath() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        cs.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        assertThrows(CredentialStoreException.class, () -> cs.getAliases(""));
    }

    private HashicorpVaultCredentialStore createHashicorpVaultCredentialStore() throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        store.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        return store;
    }

    private PasswordCredential createCredentialFromPassword(String password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, WildFlyElytronPasswordProvider.getInstance());
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }

    private CredentialStore.CredentialSourceProtectionParameter createProtectionParameter(String protectionParameter) throws UnsupportedCredentialTypeException {
        return new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword(protectionParameter)));
    }
}
