/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault.loginstrategy;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import io.github.jopenlibs.vault.VaultException;

/**
 * Login using JWT
 */
public class JwtLoginStrategy implements VaultLoginStrategy{

    @Override
    public String tryLogin(LoginContext context) throws VaultException {
        if (context.getJwtConfig() == null) {
            throw new VaultException(ROOT_LOGGER.vaultJwtConfigurationMissing());
        }
        return context.getVault().auth().loginByJwt(
                context.getJwtConfig().getJwtProvider(),
                context.getJwtConfig().getJwtRole(),
                context.getJwtConfig().getJwt()).getAuthClientToken();
    }
}
