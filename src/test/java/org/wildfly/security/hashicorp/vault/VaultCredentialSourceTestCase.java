/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.github.jopenlibs.vault.SslConfig;
import org.junit.Assert;
import org.junit.Test;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.interfaces.ClearPassword;

import java.io.IOException;

public class VaultCredentialSourceTestCase {

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
        // setup and start test container with vault
        startVaultTestContainer();

        // Start Vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "/v1/secret/data/testing2", new SslConfig().verify(false), false);

        // Test credential source with vault service
        VaultCredentialSource credentialSource = new VaultCredentialSource(vaultService, "secret/testing1", "top_secret");
        PasswordCredential credential = credentialSource.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        Assert.assertEquals("password123", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    @Test
    public void testGetSecretFromVaultServiceReturnNullWithIncorrectPath() throws Exception {
        // setup and start test container with vault
        startVaultTestContainer();

        // Start Vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "/v1/secret/data/testing2", new SslConfig().verify(false), false);

        // Test credential source with vault service
        VaultCredentialSource credentialSource = new VaultCredentialSource(vaultService, "secret/testing1", "incorrect");
        PasswordCredential credential = credentialSource.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        Assert.assertNull(credential);
    }

    @Test(expected = IOException.class)
    public void testGetSecretFromVaultServiceFailsWithIncorrectToken() throws Exception {
        // setup and start test container with vault
        startVaultTestContainer();
        // Start Vault service
        VaultConnector vaultConnector = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "incorrect", "/v1/secret/data/testing2", new SslConfig().verify(false), false);

        // Test credential source with vault service
        VaultCredentialSource credentialSource = new VaultCredentialSource(vaultConnector, "secret/testing1", "incorrect");
        credentialSource.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
    }
}
