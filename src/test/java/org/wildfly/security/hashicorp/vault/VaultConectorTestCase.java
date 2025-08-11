/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;
import org.junit.Test;
import org.testcontainers.vault.VaultContainer;

import static org.junit.Assert.assertEquals;

public class VaultConectorTestCase {

    VaultContainer<?> vaultTestContainer;

    private void startVaultTestContainer() {
        vaultTestContainer = new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultTestContainer.start();
    }

    @Test
    public void testGetSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "/v1/secret/data/testing2", new SslConfig().verify(false), false);
        vaultService.configure();
        assertEquals("password123", vaultService.getSecret("secret/testing1", "top_secret"));
    }

    @Test(expected = VaultException.class)
    public void testIncorerctVaultToken() throws Exception {
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

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "incorrect", "/v1/secret/data/testing2", new SslConfig().verify(false), false);
        vaultService.configure();
        assertEquals("password123", vaultService.getSecret("secret/testing1", "top_secret"));
    }
}
