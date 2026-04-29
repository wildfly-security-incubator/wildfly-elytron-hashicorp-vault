Contributing to WildFly Elytron HashiCorp Vault
==================================================

Welcome to the WildFly Elytron HashiCorp Vault project! We welcome contributions from the community. This guide will walk you through the steps for getting started on our project.

- [Forking the Project](#forking-the-project)
- [Issues](#issues)
  - [Good First Issues](#good-first-issues)
- [Setting up your Developer Environment](#setting-up-your-developer-environment)
- [Contributing Guidelines](#contributing-guidelines)
  - [Testing](#testing)
  - [Multi-Version Testing](#multi-version-testing)
  - [Pull Request Process](#pull-request-process)
  - [Documentation](#documentation)
- [Community](#community)

## Forking the Project 

To contribute, you will first need to fork the [wildfly-elytron-hashicorp-vault](https://github.com/wildfly-security/wildfly-elytron-hashicorp-vault) repository. 

This can be done by looking in the top-right corner of the repository page and clicking "Fork".

The next step is to clone your newly forked repository onto your local workspace. This can be done by going to your newly forked repository, which should be at `https://github.com/USERNAME/wildfly-elytron-hashicorp-vault`. 

Then, there will be a green button that says "Code". Click on that and copy the URL.

Then, in your terminal, paste the following command:
```bash
git clone [URL]
```
Be sure to replace [URL] with the URL that you copied.

Now you have the repository on your computer!

## Issues

The WildFly Elytron HashiCorp Vault project uses GitHub Issues to track bugs, feature requests, and other work items. You can view and create issues [here](https://github.com/wildfly-security/wildfly-elytron-hashicorp-vault/issues).

When working on an issue, it is recommended that you use a separate branch for every issue. To keep things straightforward and memorable, you can name each branch using the issue number. This way, you can have multiple PRs open for different issues. For example, if you were working on issue #42, you could use `issue-42` or `fix-42` as your branch name.

## Setting up your Developer Environment

You will need:

* **JDK 25 or later** (required for building)
* Git
* Maven 3.9 or later
* **Podman** (required for running tests with Testcontainers)
* An [IDE](https://en.wikipedia.org/wiki/Comparison_of_integrated_development_environments#Java)
(e.g., [IntelliJ IDEA](https://www.jetbrains.com/idea/download/), [Eclipse](https://www.eclipse.org/downloads/), etc.)

### Important: Java 25 Requirement

This project requires **Java 25** to build. The build produces Java 17 bytecode for backward compatibility, but you must have Java 25 installed and set as your `JAVA_HOME` to compile the project.

### Podman Requirement

Tests use [Testcontainers](https://www.testcontainers.org/) to spin up HashiCorp Vault instances. This requires:
- Podman installed and running
- Podman socket enabled for Testcontainers compatibility
- Sufficient permissions to run Podman containers
- Network access to pull container images

**Setting up Podman for Testcontainers**:

On Linux, start the Podman socket:
```bash
systemctl --user start podman.socket
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
```

For more details, see the [Testcontainers Podman documentation](https://podman-desktop.io/tutorial/testcontainers-with-podman).

First `cd` to the directory where you cloned the project (eg: `cd wildfly-elytron-hashicorp-vault`)

Add a remote ref to upstream, for pulling future updates.
For example:

```bash
git remote add upstream https://github.com/wildfly-security/wildfly-elytron-hashicorp-vault
```

To build `wildfly-elytron-hashicorp-vault` run:
```bash
mvn clean install
```

To skip the tests, use:
```bash
mvn clean install -DskipTests=true
```

To run only a specific test, use:
```bash
mvn clean install -Dtest=TestClassName
```

## Contributing Guidelines

### Testing

Ensure that your changes are thoroughly tested before submitting a pull request. Follow these testing guidelines:

- Run the existing unit tests using Maven: `mvn clean test`
- Include new unit tests for your code changes
- Ensure Podman is running before executing tests (required for Testcontainers)

**Note**: Tests may take longer than typical unit tests due to container startup time.

### Multi-Version Testing

This project supports testing with multiple Java versions (17, 21, and 25) to ensure compatibility across LTS releases.

#### Setting Up Toolchains (Optional)

To test with specific Java versions locally:

1. **Install multiple JDK versions**:
   - Java 17, 21, and 25
   - Both Temurin and Semeru distributions (for full CI compatibility)
   - Download from [Adoptium](https://adoptium.net/) or [IBM Semeru](https://developer.ibm.com/languages/java/semeru-runtimes/)

2. **Configure Maven toolchains**:
   - Copy `toolchains.xml.template` to `~/.m2/toolchains.xml`
   - Update the `<jdkHome>` paths to match your JDK installations
   - Verify: `mvn toolchains:display-toolchains`

3. **Test with specific Java version**:
   ```bash
   # Test with Java 17
   mvn clean test -Djdk.test.version=17
   
   # Test with Java 21
   mvn clean test -Djdk.test.version=21
   
   # Test with Java 25 (default)
   mvn clean test -Djdk.test.version=25
   
   # Test with specific distribution
   mvn clean test -Djdk.test.version=21 -Djdk.test.vendor=semeru
   
   # Test all versions at once
   mvn install -Ptest-all-versions
   ```

For more details, see [README.md](README.md) and [CI.md](CI.md).

### Pull Request Process

When submitting a PR, please keep the following guidelines in mind:

1. In general, it's good practice to squash all of your commits into a single commit. For larger changes, it's ok to have multiple meaningful commits. If you need help with squashing your commits, feel free to ask us how to do this on your pull request. We're more than happy to help!

2. If your PR addresses a GitHub issue, please reference it in the title and description. For example, for issue #42, the PR title could be `Fix #42: Add support for new Vault authentication method`.

3. Please include a clear description of what your PR does and why. If it fixes a bug, describe the bug and how your changes fix it. If it adds a feature, explain the feature and its use case.

4. Ensure all CI checks pass:
   - PR workflow tests on Linux with Java 17, 21, and 25 (both Temurin and Semeru)
   - Build succeeds with Java 25
   - All tests pass with each Java version

### Documentation

Contributors are encouraged to keep documentation up-to-date along with code changes. If your changes impact user-facing features, update the relevant documentation:

- [README.md](README.md) - Usage and configuration
- [CI.md](CI.md) - CI/CD information (if workflow changes)
- Code comments and JavaDoc

## Code Reviews

All submissions, including submissions by project members, need to be reviewed by at least one WildFly Elytron committer before being merged.

The [GitHub Pull Request Review Process](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/about-pull-request-reviews) is followed for every pull request.

## Community

For more information on how to get involved with WildFly Elytron and related projects, check out the [WildFly Elytron community](https://wildfly-security.github.io/wildfly-elytron/community/) page.

## Legal

All contributions to this repository are licensed under the [Apache License](https://www.apache.org/licenses/LICENSE-2.0), version 2.0 or later, or, if another license is specified as governing the file or directory being modified, such other license.

All contributions are subject to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/).
The DCO text is also included verbatim in the [dco.txt](dco.txt) file in the root of this repository.

## Compliance with Laws and Regulations

All contributions must comply with applicable laws and regulations, including U.S. export control and sanctions restrictions.
For background, see the Linux Foundation's guidance:
[Navigating Global Regulations and Open Source: US OFAC Sanctions](https://www.linuxfoundation.org/blog/navigating-global-regulations-and-open-source-us-ofac-sanctions).
