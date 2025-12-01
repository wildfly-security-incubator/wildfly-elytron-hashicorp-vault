package org.wildfly.security.hashicorp.vault.loginstrategy;

import io.github.jopenlibs.vault.VaultException;

/**
 * Login using Vault token. This is just a dummy implementation since token is default, and we cannot determine token
 * validity until action requiring authentication.
 */
public class TokenLoginStrategy implements  VaultLoginStrategy {

    @Override
    public String tryLogin(LoginContext context) throws VaultException {
        if (context.getToken() == null || context.getToken().trim().isEmpty()) {
            throw new VaultException("Token is null, cannot login with token");
        }
        return context.getToken();
    }
}
