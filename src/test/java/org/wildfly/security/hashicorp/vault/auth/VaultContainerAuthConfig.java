/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault.auth;

import org.testcontainers.vault.VaultContainer;

/**
 * An abstraction over auth method configuration for a vault container
 */
public interface VaultContainerAuthConfig {

    void configure(VaultContainer<?> vaultContainer);

}
