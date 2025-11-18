package org.wildfly.security.hashicorp.vault;

import org.wildfly.common.annotation.NotNull;

/**
 * Simple encapsulation of JWT login configuration
 */
public final class JwtConfig {

    private final String jwt;
    private final String jwtRole;
    private final String jwtProvider;

    public JwtConfig(@NotNull String jwt, @NotNull String jwtRole, @NotNull String jwtProvider) {
        this.jwt = checkRequired(jwt);
        this.jwtRole = checkRequired(jwtRole);
        this.jwtProvider = checkRequired(jwtProvider);
    }

    public String getJwt() {
        return jwt;
    }

    public String getJwtRole() {
        return jwtRole;
    }

    public String getJwtProvider() {
        return jwtProvider;
    }

    private String checkRequired(String value) throws IllegalArgumentException {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing required property!");
        }
        return value;
    }
}
