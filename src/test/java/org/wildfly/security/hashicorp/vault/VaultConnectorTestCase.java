/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;
import org.junit.After;
import org.junit.Test;
import org.testcontainers.vault.VaultContainer;

import static org.junit.Assert.assertEquals;

public class VaultConnectorTestCase {

    VaultContainer<?> vaultTestContainer;

    @After
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    private void startVaultTestContainer() {
        vaultTestContainer = new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 ttl=30m top_secret=password123",
                        "kv put secret/testing2 ttl=30m dbuser=secretpass jmsuser=jmspass",
                        "kv put secret/my-secret ttl=30m my-value=s3cr3t"
                );
        vaultTestContainer.start();
    }

    @Test
    public void testGetSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "secret/testing1", new SslConfig().verify(true), true);
        vaultService.configure();
        assertEquals("password123", vaultService.getSecret("secret/testing1", "top_secret"));
    }

    @Test
    public void testPutSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "secret/testing1", new SslConfig().verify(true), true);
        vaultService.configure();
        vaultService.putSecret("secret/testing1", "top_secret2", "password2");

        assertEquals("password2", vaultService.getSecret("secret/testing1", "top_secret2"));
    }

    @Test
    public void testRemoveSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "secret/testing1", new SslConfig().verify(true), true);
        vaultService.configure();
        
        // First verify the secret exists
        String originalSecret = vaultService.getSecret("secret/testing1", "top_secret");
        assertEquals("password123", originalSecret);
        
        // Remove the secret
        vaultService.removeSecret("secret/testing1", "top_secret");

        // After removal, accessing the secret should throw VaultException
        try {
            vaultService.getSecret("secret/testing1", "top_secret");
            // If we get here, the test should fail because exception was expected
            throw new AssertionError("Expected VaultException when accessing removed secret");
        } catch (VaultException e) {
            // This is expected - the secret should not be found after removal
            // Test passes if we get here
        }
    }

    @Test(expected = VaultException.class)
    public void testIncorrectVaultToken() throws Exception {
        // setup test container with vault
        vaultTestContainer = new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultTestContainer.start();

        // Test vault service with incorrect token - this should throw VaultException during configure()
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "incorrect-token", "admin", new SslConfig().verify(true), true);
        vaultService.configure(); // This should throw VaultException due to authentication failure
    }

    @Test
    public void testRemove() throws Exception {
        // setup and start test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "admin", new SslConfig().verify(true), true);
        vaultService.configure();
        vaultService.removeSecret("secret/testing1", "top_secret");
    }
}
