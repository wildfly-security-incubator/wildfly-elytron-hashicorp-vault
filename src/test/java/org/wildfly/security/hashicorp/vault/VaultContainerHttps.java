/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.smallrye.certs.CertificateFiles;
import io.smallrye.certs.CertificateGenerator;
import io.smallrye.certs.CertificateRequest;
import io.smallrye.certs.Format;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import org.testcontainers.vault.VaultContainer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Represents a {@link VaultContainer} running with a secured interface
 * This container is available at port 8400
 * See VAULT_CONFIG for details.
 */
public class VaultContainerHttps<SELF extends VaultContainerHttps<SELF>> extends VaultContainer<SELF> {

    private static final int HTTPS_PORT = 8400;

    private static final String VAULT_CONFIG = String.format(
            "listener \"tcp\" {\n" +
            "  address       = \"0.0.0.0:%d\"\n" +
            "  tls_cert_file = \"/vault/certs/vault.crt\"\n" +
            "  tls_key_file  = \"/vault/certs/vault.key\"\n" +
            "}\n" +
            "\n" +
            "storage \"file\" {\n" +
            "  path = \"/vault/data\"\n" +
            "}\n" +
            "\n" +
            "ui = false\n" +
            "\n" +
            "disable_mlock = true\n" +
            "api_addr = \"https://127.0.0.1:%d\"\n",
            HTTPS_PORT, HTTPS_PORT
    );

    public VaultContainerHttps(String dockerImageName) {
        super(dockerImageName);

        final MountableFile certs;
        final MountableFile config;

        try {
            certs = MountableFile.forHostPath(prepareCertificate(), 0777);
            config = MountableFile.forHostPath(prepareVaultConfig(VAULT_CONFIG), 0777);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        this.withCopyFileToContainer(certs, "/vault/certs")
            .withCopyFileToContainer(config, "/vault/config")
            .withExposedPorts(8200, 8400)
            .withCommand("server", "-dev");
        this.setWaitStrategy(Wait.forHttps("/v1/sys/health")
                .forPort(8400)
                .allowInsecure()
                .forResponsePredicate(response -> response.contains("\"initialized\":true")));
    }

    private static Path prepareCertificate() throws Exception {
        final Path certTmpDir = Files.createTempDirectory("vault_certs");
        final Path vaultTmpCertDir = Files.createTempDirectory("vault_certs");

        final CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PEM);

        final List<CertificateFiles> certificateFiles = new CertificateGenerator(certTmpDir, true).generate(request);

        final CertificateFiles pemFiles = certificateFiles.get(0);

        final Path certPath = pemFiles.root().resolve("test.crt");
        final Path keyPath  = pemFiles.root().resolve("test.key");

        Files.copy(certPath, vaultTmpCertDir.resolve("vault.crt"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        Files.copy(keyPath,  vaultTmpCertDir.resolve("vault.key"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        return vaultTmpCertDir;
    }

    private static Path prepareVaultConfig(String config) throws IOException {
        final Path vaultConfigDir = Files.createTempDirectory("vault_config");
        final Path vaultConfigFile = vaultConfigDir.resolve("config.hcl");
        Files.writeString(vaultConfigFile, config);
        return vaultConfigDir;
    }

    /**
     * Retrieve HTTPS address of the Vault
     */
    public String composeHttpsHostAddress() {
        return String.format("https://%s:%s", this.getHost(), this.getMappedPort(HTTPS_PORT));
    }
}
