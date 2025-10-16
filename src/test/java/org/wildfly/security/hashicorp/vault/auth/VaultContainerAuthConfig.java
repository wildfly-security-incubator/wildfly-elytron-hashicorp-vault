package org.wildfly.security.hashicorp.vault.auth;

import org.testcontainers.vault.VaultContainer;

/**
 * An abstraction over auth method configuration for a vault container
 */
public interface VaultContainerAuthConfig {

    void configure(VaultContainer<?> vaultContainer);

}
