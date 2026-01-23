/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault.loginstrategy;

import io.github.jopenlibs.vault.VaultException;

/**
 * Login using Vault token provided in the configuration. We cannot determine token validity until action requiring
 * authentication happens so this is just a check for token presence.
 */
public class TokenLoginStrategy implements VaultLoginStrategy {

    @Override
    public String tryLogin(LoginContext context) throws VaultException {
        if (context.getToken() == null || context.getToken().trim().isEmpty()) {
            throw new VaultException("Token is null, cannot login with token");
        }
        return context.getToken();
    }
}
