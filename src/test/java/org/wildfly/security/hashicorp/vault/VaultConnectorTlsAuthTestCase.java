/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.wildfly.security.hashicorp.vault.auth.TlsCertAuthConfig;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Set of tests verifying functionality of VaultConnector when using TLS certificate authentication method
 */
public class VaultConnectorTlsAuthTestCase {

    private VaultContainerHttps<?> vaultTestContainer;

    private static SslConfig permissibleSslAuthConfig;

    @BeforeEach
    public void beforeEach() throws Exception {
        vaultTestContainer = new VaultContainerHttps<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 ttl=30m top_secret=password123",
                        "kv put secret/testing2 ttl=30m dbuser=secretpass jmsuser=jmspass",
                        "kv put secret/my-secret ttl=30m my-value=s3cr3t"
                );

        new TlsCertAuthConfig.Builder(vaultTestContainer.getClientCertificateFiles())
                //this is a custom policy created in VaultContainerHttps since we cannot use root policy
                .policies("admin")
                .build()
                .configure(this.vaultTestContainer);

        permissibleSslAuthConfig = new SslConfig()
                //to enable HTTPS
                .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                //for TLS certificate auth method
                .clientPemFile(vaultTestContainer.getClientCertificateFiles().clientCertFile().toFile())
                .clientKeyPemFile(vaultTestContainer.getClientCertificateFiles().clientKeyFile().toFile())
                .verify(true)
                .build();

        vaultTestContainer.start();
    }

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    /**
     * Configure vault connector with proper SSL config and no token and obtain a secret from the vault.
     * Test will succeed when connector properly uses login by crt auth method and reuses obtained token.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n"})
    public void testGetSecretFromVaultService(final String token) throws VaultException {
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), token, "secret/testing1", permissibleSslAuthConfig, true);
        vaultService.configure();
        assertEquals("password123", vaultService.getSecret("secret/testing1", "top_secret"));
    }

    /**
     * Configure vault connector with proper SSL config and an invalid token and try to obtain a secret from the vault.
     * Test will fail since the connector will try to use the token to authenticate.
     */
    @Test
    public void testGetSecretFromVaultServiceInvalidToken() {
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "invalidToken", "secret/testing1", new SslConfig().verify(true), true);
        assertThrows(VaultException.class, vaultService::configure,
                "Correct SSL auth config was provided but token was non-empty and invalid. This should fail.");
    }

    /**
     * Configure vault connector with proper SSL config and no token. Try to obtain a secret from the vault and then
     * remove it. Validate the new value of obtained secret is null.
     * Test will succeed when the secret is obtained removed and obtained again.
     */
    @Test
    public void testRemoveSecretFromVaultService() throws Exception {
        final VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "", "secret/testing1", permissibleSslAuthConfig, true);
        vaultService.configure();

        final String originalSecret = vaultService.getSecret("secret/testing1", "top_secret");
        assertEquals("password123", originalSecret);

        vaultService.removeSecret("secret/testing1", "top_secret");

        assertNull(vaultService.getSecret("secret/testing1", "top_secret"));
    }

}
