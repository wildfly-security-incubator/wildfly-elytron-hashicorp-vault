# Continuous Integration

WildFly Elytron HashiCorp Vault uses GitHub Actions for continuous integration testing across multiple Java versions, vendors, and operating systems.

## Overview

The CI infrastructure is designed to:
- Build once with Java 25 (producing Java 17 bytecode)
- Test across multiple Java LTS versions (17, 21, 25)
- Test with multiple JDK vendors (Temurin and Semeru)
- Test on multiple operating systems (Linux, Windows, macOS)
- Support testing of non-LTS Java versions (e.g., Java 26)

**Note**: Due to Testcontainers dependency, full test execution requires Podman (or Docker) and is only performed on Linux runners.

## Workflows

### PR Workflow (`pr-ci.yml`)

**Trigger**: Pull requests to the main branch

**Scope**: Linux-only testing with 6 test permutations:
- Java 17 (Temurin, Semeru)
- Java 21 (Temurin, Semeru)
- Java 25 (Temurin, Semeru)

**Process**:
1. Installs all 6 JDKs
2. Builds project once with Java 25
3. Runs tests sequentially with each JDK permutation
4. Publishes test results to PR (6 separate checks)
5. Uploads test artifacts on failure

**Test Result Checks**:
- "Test Results - Java 17 (Temurin) - Linux"
- "Test Results - Java 17 (Semeru) - Linux"
- "Test Results - Java 21 (Temurin) - Linux"
- "Test Results - Java 21 (Semeru) - Linux"
- "Test Results - Java 25 (Temurin) - Linux"
- "Test Results - Java 25 (Semeru) - Linux"

**Why Linux Only?**
- Testcontainers requires a container runtime (Podman or Docker)
- GitHub Actions provides Docker on Linux runners by default
- Windows and macOS runners don't have container runtimes pre-installed
- This keeps PR feedback fast while ensuring comprehensive testing

### LTS Nightly Workflow (`ci-lts-nightly.yml`)

**Trigger**: Daily at 2 AM UTC, push to main branch, or manual via workflow_dispatch

**Scope**: Full matrix testing (18 permutations)

**Test Matrix**:
- 3 operating systems: Linux, Windows, macOS
- 3 Java versions: 17, 21, 25
- 2 JDK vendors: Temurin, Semeru
- Total: 18 permutations (3 OS × 6 test runs per OS)

**Process** (per OS):
1. Installs all 6 JDKs (Java 17, 21, 25 × Temurin, Semeru)
2. Builds project once with Java 25
3. Runs tests sequentially with each JDK permutation (Linux only)
4. Publishes test results (6 checks on Linux)
5. Uploads test artifacts on failure

**Platform-Specific Behavior**:
- **Linux**: Full build and test execution (6 test permutations)
- **Windows**: Build only (no tests due to container runtime requirement)
- **macOS**: Build only (no tests due to container runtime requirement)

**Purpose**: Comprehensive validation across all supported platforms and JDK combinations

### Non-LTS Workflow (`ci-non-lts.yml`)

**Trigger**: Daily at 3 AM UTC, or manual via workflow_dispatch

**Scope**: Java 26 testing (6 permutations)

**Test Matrix**:
- 3 operating systems: Linux, Windows, macOS
- 1 Java version: 26
- 2 JDK vendors: Temurin, Semeru
- Total: 6 permutations (3 OS × 2 test runs per OS)

**Process**:
1. Installs Java 25 (for build) and Java 26 (for test)
2. Builds project with Java 25
3. Runs tests with Java 26 (Linux only)
4. Publishes test results (2 checks on Linux)
5. Uploads test artifacts on failure

**Purpose**: Early detection of compatibility issues with upcoming Java releases

**Note**: This workflow can be disabled during LTS transition periods by setting the `enabled` input to `false` when manually triggering.

## Understanding Test Results

### Test Result Checks

Each test permutation creates a separate check in the PR or workflow run:
- Format: `Test Results - Java {version} ({vendor}) - {os}`
- Example: `Test Results - Java 21 (Semeru) - Linux`

### Test Result Artifacts

When tests fail, artifacts are automatically uploaded:
- **Naming**: `test-results-java{version}-{vendor}-{os}`
- **Retention**: 30 days
- **Contents**: Surefire test reports from failed permutation

Example artifact names:
- `test-results-java17-temurin-linux`
- `test-results-java21-semeru-linux`

### Interpreting Results

**All Green**: All test permutations passed
**Some Red**: Specific Java version/vendor/OS combination failed
**All Red**: Likely a build failure or widespread test issue

**Build-Only Platforms**: Windows and macOS show successful builds but no test results (expected behavior due to container runtime requirement)

## Troubleshooting Test Failures

### Step 1: Identify the Failing Permutation

Check which specific combination failed:
- Java version (17, 21, 25, or 26)
- JDK vendor (Temurin or Semeru)
- Operating system (Linux only for test failures)

### Step 2: Download Test Artifacts

1. Go to the failed workflow run
2. Scroll to "Artifacts" section at bottom
3. Download the artifact for the failed permutation
4. Extract and examine surefire reports

### Step 3: Reproduce Locally

Use Maven toolchains to reproduce the failure:

```bash
# Test with specific Java version
mvn test -Djdk.test.version=21

# Test with specific vendor
mvn test -Djdk.test.version=21 -Djdk.test.vendor=semeru

# Run all permutations
mvn install -Ptest-all-versions
```

See [README.md](README.md) for toolchains setup instructions.

### Step 4: Common Issues

**Testcontainers Issues**:
- Ensure Podman (or Docker) is running locally
- For Podman: Verify socket is enabled (`systemctl --user status podman.socket`)
- Check container image availability
- Verify network connectivity for image pulls
- Increase test timeout if needed

**Vendor-Specific Failures**:
- Semeru uses OpenJ9 JVM (different from HotSpot)
- Check for JVM-specific behavior assumptions
- Review garbage collection or memory management differences

**Version-Specific Failures**:
- Check for deprecated API usage
- Review SecurityManager-related code (not supported in Java 25+)
- Verify bytecode compatibility

**HashiCorp Vault Integration**:
- Verify vault-java-driver compatibility
- Check Vault container startup issues
- Review Vault API version compatibility

## Manual Workflow Triggers

All workflows support manual triggering via `workflow_dispatch`:

1. Go to "Actions" tab in GitHub
2. Select the workflow (e.g., "CI - LTS Nightly")
3. Click "Run workflow" button
4. Select branch (main)
5. For non-LTS workflow: Optionally disable by setting `enabled` to `false`
6. Click "Run workflow"

This is useful for:
- Testing changes before merge
- Verifying fixes for specific platforms
- Running full test matrix on demand
- Disabling non-LTS testing during transition periods

## Workflow Maintenance

### Updating Java Versions

When a new Java LTS version is released:

1. Update LTS workflow (`ci-lts-nightly.yml`):
   - Add new Java version to JDK installation steps
   - Add new test execution steps
   - Update test result publishing steps

2. Update PR workflow (`pr-ci.yml`):
   - Add new Java version to JDK installation steps
   - Add new test execution steps
   - Update test result publishing steps

3. Update POM (`pom.xml`):
   - Add new Java version to `test-all-versions` profile

4. Update documentation:
   - README.md
   - This file (CI.md)
   - toolchains.xml.template

### Disabling Non-LTS Workflows

During LTS transition periods (e.g., when Java 27 is about to become Java 28 LTS):

1. Manually trigger the workflow with `enabled: false`
2. Or comment out the schedule trigger in `ci-non-lts.yml`
3. Keep workflow file for manual triggering if needed
4. Re-enable when new non-LTS version is available

### Container Runtime and Testcontainers

**Current Limitation**: Tests only run on Linux due to container runtime requirement

**Future Considerations**:
- GitHub Actions may add container runtime support to Windows/macOS runners
- Alternative: Use remote Podman/Docker daemon for Windows/macOS testing
- Alternative: Mock Vault integration for non-Linux platforms

**Note**: While CI uses Docker (pre-installed on GitHub Actions Linux runners), local development can use either Podman or Docker. See [README.md](README.md) for Podman setup instructions.

## Related Documentation

- [README.md](README.md) - Build and test instructions
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [toolchains.xml.template](toolchains.xml.template) - Toolchains configuration template
