# WildFly HashiCorp Vault Credential Store

A credential store implementation for WildFly that integrates with HashiCorp Vault for secure credential storage and retrieval.

## Requirements

- HashiCorp Vault server
- WildFly server 
- Java
- Maven
- Vault Java driver

## Build the project

```bash
git clone <repository-url>
cd wildfly-elytron-hashicorp-vault
mvn clean install
```
# Important

Adding a credential store to the Elytron subsystem is only a preview of what we are working on. Using it this way is not recommended. We are currently developing a dedicated feature pack with a vault subsystem that will offer more configuration options.


## Configuration

### 1. Add the Credential Store to WildFly

Connect to the CLI and add the HashiCorp Vault credential store to your WildFly configuration:

```bash
# Using WildFly CLI
$WILDFLY_HOME/bin/jboss-cli.sh --connect
/subsystem=elytron/credential-store=vault-token-store:add-alias(alias=vault-token, secret-value=hvs.your-vault-token-here)

module add --name=io.github.jopenlibs.vault --resources=/path/to/vault-java-driver/vault-java-driver-x.y.z.jar

module add --name=org.wildfly.vaultcredentialstore --resources=/path/to/repo/target/wildfly-elytron-hashicorp-vault-1.0-SNAPSHOT.jar --dependencies=org.wildfly.security.elytron,io.github.jopenlibs.vault

/subsystem=elytron/provider-loader=vaultProviderLoader:add(class-names=[org.wildfly.security.hashicorp.vault.HashicorpVaultCredentialStoreProvider],module=org.wildfly.vaultcredentialstore)

/subsystem=elytron/credential-store=vault-store:add(providers=vaultProviderLoader,implementation-properties={host-address="https://localhost:9200", trustStorePath="/path/to/client.truststore.jks"},type=HashicorpVaultCredentialStore,credential-reference={clear-text="myroot"})
```

Example result configuration (`standalone.xml` or `domain.xml`):

```xml
<subsystem xmlns="urn:wildfly:elytron:15.0">
    ...
    <credential-stores>
        <credential-store name="vault-store" 
                         type="HashicorpVaultCredentialStore"
                         providers="vaultProviderLoader">
            <implementation-properties>
                <property name="host-address" value="https://vault.example.com:8200"/>
                <property name="namespace" value="production"/>
                <property name="trustStorePath" value="/path/to/vault-truststore.jks"/>
                <property name="keyStorePath" value="/path/to/vault-keystore.jks"/>
                <property name="keyStorePass" value="keystore-password"/>
            </implementation-properties>
            <credential-reference clear-text="root-token-id"/>
        </credential-store>
    ...
</subsystem>
```

### 2. Use the Credential Store

**Note:** The alias format is: `<vault-path>.<key>`

```bash
/subsystem=elytron/credential-store=vault-store:add-alias(alias="/secrets/test.db_user", secret-value="db_user_pass")
```

Reference credentials from Vault in your WildFly configuration:

```xml
<!-- Example: Database connection using Vault-stored password -->
<subsystem xmlns="urn:jboss:domain:datasources:7.0">
    <datasources>
        <datasource jndi-name="java:jboss/datasources/MyAppDS" pool-name="MyAppDS">
            <connection-url>jdbc:postgresql://localhost:5432/myapp</connection-url>
            <driver>postgresql</driver>
            <security>
                <user-name>dbuser</user-name>
                <credential-reference store="vault-store" alias="secret/myapp.database_password"/>
            </security>
        </datasource>
    </datasources>
</subsystem>

<!-- Example: Security domain using Vault-stored LDAP password -->
<subsystem xmlns="urn:wildfly:elytron:15.0">
    <security-domains>
        <security-domain name="MyAppDomain" default-realm="ldap-realm"/>
    </security-domains>
    <security-realms>
        <ldap-realm name="ldap-realm" dir-context="ldap-connection">
            <identity-mapping rdn-identifier="uid" search-base-dn="ou=users,dc=example,dc=com"/>
        </ldap-realm>
    </security-realms>
    <dir-contexts>
        <dir-context name="ldap-connection" url="ldap://ldap.example.com:389">
            <credential-reference store="vault-store" alias="secret/ldap.bind_password"/>
        </dir-context>
    </dir-contexts>
</subsystem>
```

## Configuration Properties

| Property | Required | Description | Example |
|----------|----------|-------------|---------|
| `host-address` | Yes | Vault server URL | `https://vault.example.com:8200` |
| `namespace` | No | Vault namespace (Enterprise) | `production` |
| `trustStorePath` | No | Path to trust store for SSL | `/path/to/truststore.jks` |
| `keyStorePath` | No | Path to key store for client auth | `/path/to/keystore.jks` |
| `keyStorePass` | No | Key store password | `keystore-password` |

## Quickstart example

You can run a vault container with Docker to try this library:

```bash
docker run --cap-add=IPC_LOCK  -p 8200:8200 -p 9200:9200 -e 'VAULT_DEV_LISTEN_ADDRESS=localhost:8200' -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot'  -e 'VAULT_LOCAL_CONFIG={"listener":[{"tcp":{"address":"0.0.0.0:9200","tls_cert_file":"/vault/config/tls/vault_server.cer", "tls_key_file":"/vault/config/tls/private_key.pem"}}]}' -v $(pwd):"/vault/config/tls":Z  hashicorp/vault
```

Run the above in the folder where you have your server certificate and private key. You can configure a credential store that connects to the above with e.g.:

```bash
/subsystem=elytron/credential-store=vault_store:add(providers=vaultProviderLoader,implementation-properties={host-address="https://localhost:9200", trustStorePath="/path/to/client.truststore.jks"},type=HashicorpVaultCredentialStore,credential-reference={clear-text="myroot"})
```

## Using Podman instead of Docker

To use Podman instead of Docker on Linux:

Start the Podman daemon in the background:
```bash
$ systemctl --user start podman.socket &
```

Set the DOCKER_HOST environmental variable:
```bash
$ export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
```
See https://podman-desktop.io/tutorial/testcontainers-with-podman for more details.

## License

Licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.