/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import io.smallrye.certs.CertificateFiles;
import io.smallrye.certs.CertificateGenerator;
import io.smallrye.certs.CertificateRequest;
import io.smallrye.certs.Format;
import org.jboss.logging.Logger;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.hashicorp.vault.logging.JbossLoggingLogConsumer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

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

    private final Path generatedCertificatesDir;
    private final Path mountedVaultCertsDir;
    private final Path mountedVaultConfigDir;

    public VaultContainerHttps(String dockerImageName) {
        super(dockerImageName);

        final MountableFile certs;
        final MountableFile config;

        try {
            this.generatedCertificatesDir = Files.createTempDirectory("generated_certificates");
            this.mountedVaultCertsDir = Files.createTempDirectory("vault_certs");
            this.mountedVaultConfigDir = Files.createTempDirectory("vault_config");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            certs = MountableFile.forHostPath(prepareCertificate(this.generatedCertificatesDir, this.mountedVaultCertsDir), 0777);
            config = MountableFile.forHostPath(prepareVaultConfig(VAULT_CONFIG, this.mountedVaultConfigDir), 0777);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        this.withCopyFileToContainer(certs, "/vault/certs")
                .withCopyFileToContainer(config, "/vault/config")
                .withExposedPorts(8200, HTTPS_PORT)
                .withLogConsumer(new JbossLoggingLogConsumer(Logger.getLogger("HTTPS_VAULT_CONTAINER")))
                .withCommand("server", "-dev");
        this.setWaitStrategy(Wait.forHttps("/v1/sys/health")
                .forPort(HTTPS_PORT)
                .allowInsecure()
                .forResponsePredicate(response -> response.contains("\"initialized\":true")));
    }

    private static Path prepareCertificate(final Path certTmpDir, final Path vaultTmpCertDir) throws Exception {
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

    private static Path prepareVaultConfig(String config, final Path vaultConfigDir) throws IOException {
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

    @Override
    public void close() {
        super.close();
        cleanupDir(this.generatedCertificatesDir);
        cleanupDir(this.mountedVaultCertsDir);
        cleanupDir(this.mountedVaultConfigDir);
    }

    private void cleanupDir(final Path dir) {
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.forEach(path -> {
                try {
                    Files.delete(path);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
