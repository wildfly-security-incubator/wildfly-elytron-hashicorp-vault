/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import org.testcontainers.vault.VaultContainer;

public class VaultTestUtils {

    /**
     * Starts a Vault test container with predefined secrets.
     */
    public static VaultContainer<?> startVaultTestContainer() {
        VaultContainer<?> vaultTestContainer = new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultTestContainer.start();
        return vaultTestContainer;
    }
}
