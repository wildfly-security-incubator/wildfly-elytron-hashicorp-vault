/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Dedicated tests for Vault listening on HTTPS interface
 */
public class VaultConnectorHttpsTestCase {

    private VaultContainerHttps<?> vaultTestContainer;

    private SslConfig httpsSslConfig;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    private void startVaultTestContainer() throws IOException, VaultException {
        vaultTestContainer = new VaultContainerHttps<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 ttl=30m top_secret=password123",
                        "kv put secret/testing2 ttl=30m dbuser=secretpass jmsuser=jmspass",
                        "kv put secret/my-secret ttl=30m my-value=s3cr3t"
                );
        vaultTestContainer.start();

        httpsSslConfig = new SslConfig()
                //to enable HTTPS
                .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                .verify(true)
                .build();
    }

    @Test
    public void testGetSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "myroot", "secret/testing1", httpsSslConfig, true);
        vaultService.configure();
        assertEquals("password123", vaultService.getSecret("secret/testing1", "top_secret"));
    }

    @Test
    public void testPutSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "myroot", "secret/testing1", httpsSslConfig, true);
        vaultService.configure();
        vaultService.putSecret("secret/testing1", "top_secret2", "password2");

        assertEquals("password2", vaultService.getSecret("secret/testing1", "top_secret2"));
    }

    @Test
    public void testRemoveSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "myroot", "secret/testing1", httpsSslConfig, true);
        vaultService.configure();

        // First verify the secret exists
        String originalSecret = vaultService.getSecret("secret/testing1", "top_secret");
        assertEquals("password123", originalSecret);

        // Remove the secret
        vaultService.removeSecret("secret/testing1", "top_secret");

        assertNull(vaultService.getSecret("secret/testing1", "top_secret"));
        // If we get here, the test should fail because exception was expected

    }

    @Test
    public void testIncorrectVaultToken() throws Exception {
        // setup test container with vault
        vaultTestContainer = new VaultContainerHttps<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultTestContainer.start();

        // Test vault service with incorrect token - this should throw VaultException during configure()
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "incorrect-token", "admin", httpsSslConfig, true);
        assertThrows(VaultException.class, vaultService::configure,
                "VaultException should be thrown due to authentication failure");
    }

    @Test
    public void testRemove() throws Exception {
        // setup and start test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "myroot", "admin", httpsSslConfig, true);
        vaultService.configure();
        vaultService.removeSecret("secret/testing1", "top_secret");
    }
}
