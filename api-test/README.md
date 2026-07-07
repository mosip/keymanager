# Key Manager API Test Rig

## Overview

The **Key Manager API Test Rig** is designed for the execution of module-wise automation API tests for the MOSIP Key Manager service. This test rig utilizes **Java REST Assured** and **TestNG** frameworks to automate testing of the Key Manager API functionalities. The key focus is to validate master key generation, CSR generation, certificate upload/validation, EC sign key generation and related key management functionalities provided by the Key Manager module.

---

## Test Categories

- **Smoke**: Contains only positive test scenarios for quick verification.
- **Regression**: Includes all test scenarios, covering both positive and negative cases.

---

## Coverage

This test rig covers only **external API endpoints** exposed by the Key Manager service module.

---

## Pre-requisites

Before running the automation tests, ensure the following software is installed on the machine:

- **Java 21** ([download here](https://jdk.java.net/))
- **Maven 3.9.6** or higher ([installation guide](https://maven.apache.org/install.html))
- **Lombok** (Refer to [Lombok Project](https://projectlombok.org/))
- **settings.xml** ([download here](https://github.com/mosip/mosip-functional-tests/blob/master/settings.xml))

### For Windows

- **Git Bash 2.18.0** or higher
- Ensure the `settings.xml` file is present in the `.m2` folder.

### For Linux

- The `settings.xml` file should be present in two places:
  - In the regular Maven configuration folder (`/conf`)
  - Under `/usr/local/maven/conf/`

### Shared commons library

All modules depend on `apitest-commons`. If it changed locally, rebuild it before rebuilding this module:

```sh
cd mosip-functional-tests/apitest-commons
mvn clean install -Dgpg.skip=true -Dmaven.gitcommitid.skip=true
```

---

## Access Test Automation Code

You can access the test automation code using either of the following methods:

### From Browser

1. Clone or download the repository as a zip file from [GitHub](https://github.com/mosip/keymanager).
2. Unzip the contents to your local machine.
3. Open a terminal (Linux) or command prompt (Windows) and continue with the following steps.

### From Git Bash

1. Copy the Git repository URL: `https://github.com/mosip/keymanager`
2. Open **Git Bash** on your local machine.
3. Run the following command to clone the repository:
   ```sh
   git clone https://github.com/mosip/keymanager
   ```

---

## Update the property file

1. Navigate to the `keymanager.properties` file located at:
   `keymanager/api-test/src/main/resources/config/keymanager.properties`
2. Open the file in your preferred editor.
3. Update the Keycloak/database passwords and client secret values as per your environment. These are intentionally left blank in the repository and must never be committed with real values.

---

## Build Test Automation Code

Once the repository is cloned or downloaded, follow these steps to build and install the test automation code:

1. Navigate to the project directory:
   ```sh
   cd api-test
   ```

2. Build the project using Maven:
   ```sh
   mvn clean install -Dgpg.skip=true -Dmaven.gitcommitid.skip=true
   ```

This will download the required dependencies and prepare the test suite for execution.

---

## Execute Test Automation Suite

You can execute the test automation code using any of the following methods:

### Using Jar

1. Navigate to the `target` directory where the JAR file is generated:
   ```sh
   cd target/
   ```

2. Run the automation test suite JAR file:
   ```sh
   java -Dmodules=keymanager -Denv.user=<env_name> -Denv.endpoint=<base_env> -Denv.testLevel=smokeAndRegression -Xmx2G -jar apitest-keymanager-1.0.0-SNAPSHOT-jar-with-dependencies.jar
   ```

### Using Maven

```sh
mvn clean install -Dgpg.skip=true -Dmaven.gitcommitid.skip=true -Dmodules=keymanager -Denv.user=<env_name>
```

### Using Eclipse IDE

1. **Install Eclipse (Latest Version)** — download from the [Eclipse Downloads](https://www.eclipse.org/downloads/) page.

2. **Import the Maven Project**
   - Open Eclipse IDE.
   - Go to `File` > `Import`.
   - In the **Import** wizard, select `Maven` > `Existing Maven Projects`, then click **Next**.
   - Browse to the location where the `api-test` folder is saved (either from the cloned Git repository or downloaded zip).
   - Select the folder, and Eclipse will automatically detect the Maven project. Click **Finish** to import the project.

3. **Build the Project**
   - Right-click on the project in the **Project Explorer** and select `Maven` > `Update Project`.
   - This will download the required dependencies as defined in the `pom.xml` and ensure everything is correctly set up.

4. **Create a Run Configuration**
   - Go to `Run` > `Run Configurations`.
   - Right-click on **Java Application** and select **New**.
   - In the **Main** tab, select the project and set the **Main class** to `io.mosip.testrig.apirig.keymanager.testrunner.MosipTestRunner`.
   - In the **Arguments** tab, add the following **VM arguments**:
     ```
     -Dmodules=keymanager -Denv.user=<env_name> -Denv.endpoint=<base_env> -Denv.testLevel=smokeAndRegression -Xmx2G
     ```
   - Click **Run** (or **Debug** to troubleshoot with breakpoints).

### Using IntelliJ IDEA

1. Open the `api-test` folder (or the `keymanager` repo root) in IntelliJ IDEA as a Maven project and let it import.
2. A shared run configuration named **KeyManager API Tests** is checked in under `.idea/runConfigurations/` and should appear automatically in the Run/Debug configurations dropdown.
3. Edit that configuration (or create your own `Application` configuration) and replace `<env_name>` / `<base_env>` in the **VM options** field with your target environment:
   ```
   -Dmodules=keymanager -Denv.user=<env_name> -Denv.endpoint=<base_env> -Denv.testLevel=smokeAndRegression -Xmx2G
   ```
   - Main class: `io.mosip.testrig.apirig.keymanager.testrunner.MosipTestRunner`
   - Working directory: `api-test`
4. Click **Run** or **Debug**.

### Using VS Code

1. Open the `api-test` folder in VS Code with the **Extension Pack for Java** installed.
2. A launch configuration named **KeyManager API Tests** is checked in under `.vscode/launch.json`.
3. Update the `<env_name>` / `<base_env>` placeholders in `vmArgs` to match your target environment.
4. Use the **Run and Debug** panel to launch or debug `KeyManager API Tests`.

---

## 6. View Test Results

- After the tests are executed, you can view the detailed results in the `api-test/testng-report` directory.
- The report will have two sections:
  - One section for pre-requisite APIs test cases.
  - Another section for core test cases.

---

## Test Report Column Definitions

This section describes the meaning of each column in the test report:
- **Total (T)** — The total number of test cases considered in the report.
- **Passed (P)** — Indicates the number of test cases that executed successfully with the expected results.
- **Failed (F)** — Indicates the number of test cases that failed due to issues such as output validation mismatches or unexpected errors during execution.
- **Skipped (S)** — Represents test cases that were not executed due to missing prerequisites or data dependencies.
- **Ignored (I)** — Represents test cases that were intentionally not executed due to limitations such as unsupported features, incompatibilities, or undeployed services.
- **Known Issues (KI)** — Indicates test cases that failed but are already acknowledged as known issues for the current release, typically linked with a bug or defect ID.

## Details of Arguments Used

- **env.user**: Replace `<env_name>` with the appropriate environment name (e.g., `dev`, `qa`, etc.).
- **env.endpoint**: The environment where the application under test is deployed. Replace `<base_env>` with the correct base URL for the environment (e.g., `https://api-internal.<env_name>.mosip.net`).
- **env.testLevel**: Set this to `smoke` to run only smoke test cases, or `smokeAndRegression` to run both smoke and regression tests.
- **jar**: Specify the name of the JAR file to execute. The version will change according to the development code version — for example, the current version is `apitest-keymanager-1.0.0-SNAPSHOT-jar-with-dependencies.jar`.

### Running a subset of test cases

Set `testCasesToExecute` in `keymanager.properties` to a comma-separated list of `uniqueIdentifier` values, or use `moduleNamePattern` for module-level filtering:

```properties
testCasesToExecute = TC_KeyManager_GetCertificate_01,TC_KeyManager_GenerateCSR_01
moduleNamePattern = (keymanager)
```

To skip specific test cases at runtime, add their names (one per line) to `src/main/resources/testCaseSkippedList.txt` — these are loaded at startup and silently skipped.

---

## License

This project is licensed under the terms of the [Mozilla Public License 2.0](https://github.com/mosip/mosip-platform/blob/master/LICENSE)