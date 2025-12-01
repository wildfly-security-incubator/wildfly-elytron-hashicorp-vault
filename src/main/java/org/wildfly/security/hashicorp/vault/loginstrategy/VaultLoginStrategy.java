package org.wildfly.security.hashicorp.vault.loginstrategy;

import io.github.jopenlibs.vault.VaultException;

/**
 * Description of strategy for Vault login
 */
public interface VaultLoginStrategy {

    /**
     * Try login with the strategy
     * @param context current login context
     * @return token if login was successful
     * @throws VaultException thrown when anything goes wrong
     */
    String tryLogin(LoginContext context) throws VaultException;

}
