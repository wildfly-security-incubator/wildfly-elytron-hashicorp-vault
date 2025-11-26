package org.wildfly.security.hashicorp.vault.loginstrategy;

import io.github.jopenlibs.vault.VaultException;

/**
 * Login using of TLS client certificate
 */
public class ClientCertificateLoginStrategy implements VaultLoginStrategy{

    @Override
    public String tryLogin(LoginContext context) throws VaultException {
        return context.getVault().auth().loginByCert().getAuthClientToken();
    }

}
