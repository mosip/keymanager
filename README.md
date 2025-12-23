[![Maven Package upon a push](https://github.com/mosip/keymanager/actions/workflows/push-trigger.yml/badge.svg?branch=master)](https://github.com/mosip/keymanager/actions/workflows/push-trigger.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?branch=master)](https://sonarcloud.io/dashboard?branch=master)

# Key Manager

## Overview
The Key Manager Service provides secure storage, provisioning and management of cryptographic keys. It manages the key lifecycle, including generation, distribution, revocation, and auto generation upon expire. It also supports essential cryptographic operations, including encryption/decryption and digital signature generation/verification. Additionally, it maintains a centralized trust store for validating partner digital certificates and their complete trust chains.

Reference: [Key Manager](https://docs.mosip.io/1.2.0/id-lifecycle-management/supporting-components/keymanager) for more details.

## Features
- **Cryptographic Operations**: Encryption, Decryption, Digital Signature, and Verification.
- **Key Lifecycle Management**: Generation, Rotation, Revocation, and Expiry of keys.
- **Trust Store**: Centralized trust store for partner trust path validation.
- **HSM Integration**: Supports HSM through PKCS#11; SoftHSM can be used locally for simulation.
- **Zero-Knowledge Encryption/Decryption**: Supports Zero-Knowledge encryption and decryption for data protection.
- **Key Hierarchy**: Manages Root, Module, and Encryption/Decryption keys.

## Services
- **kernel-keymanager-service**: Core microservice that exposes REST APIs.
- **keys-generator**: Utility job used to generate the initial set of cryptographic keys required by MOSIP.
- **keys-migrator**: Utility tool used to securely migrate cryptographic keys between HSMs.

> **Note**: Use Mosip Auth Adaptor for authentication and authorization to access the Rest APIs.

## Local Setup
There are two ways to set up the Key Manager service locally:
1. [Local Deployment](#local-deployment) (Running the JAR file)
2. [Local Setup using Docker](#local-setup-using-docker-image)

## Pre-requisites
- JDK 21 or higher
- Maven 3.9.x
- PostgreSQL 10 or higher
- SoftHSM, HSM, PKCS12(.p12) file or JCE
- Docker (for Docker-based setup)

## Database Setup
The Key Manager service requires a PostgreSQL database to store its data.
Follow the steps below to set up the database:

**Clone the Repository**
   ```bash
   git clone https://github.com/mosip/keymanager.git
   ```

**Option 1: Using Deployment Script (Recommended)**
1. Navigate to the `keymanager/db_scripts/mosip_keymgr` directory.
2. Run the `deploy.sh` script.

   ```bash
   cd keymanager/db_scripts/mosip_keymgr
   ./deploy.sh
   ```

**Option 2: Manual Setup**
1. Create a database
   Log into postgresql and create a database for the Key Manager service.
```sql
CREATE DATABASE mosip_keymgr;
```
2. Create a schema
   Log into postgresql and create a schema for the Key Manager service.
```sql
CREATE SCHEMA keymgr;
```
3. Run the SQL scripts provided in the `db_scripts` directory to create the necessary tables and indexes.

4. Run dml scripts provided in the `db_scripts/mosip_keymgr/dml` directory to create the necessary data.

Refer to the `db_scripts` directory for more details.

## Configurations
The service configuration can be found in `kernel/kernel-keymanager-service/src/main/resources/application-local.properties`. Key configurations include:

1. HSM Configuration
- `mosip.kernel.keymanager.hsm.keystore-type`: Type of keystore (Supported Keystore Types: PKCS11, Offline, PKCS12 and JCE).
- `mosip.kernel.keymanager.hsm.config-path`: Path to the HSM configuration file.
- `mosip.kernel.keymanager.hsm.keystore-pass`: Password for the HSM keystore.

2. Database Configuration
- `keymanager_database_url`: Database connection URL.
- `keymanager_database_username`: Database username.
- `keymanager_database_password`: Database password.

## Local Deployment

1. **Clone the Repository**
   ```bash
   git clone https://github.com/mosip/keymanager.git
   ```

2. **Build the Project**
   Navigate to the kernel directory and build the project.
   ```bash
   cd kernel
   mvn clean install -Dgpg.skip=true
   ```
   *Optionally, to skip test cases:*
   ```bash
   mvn clean install -Dgpg.skip -Dmaven.test.skip=true
   ```

3. **Run the Service**
   Navigate to the service directory and run the application.
   ```bash
   cd kernel-keymanager-service
   java -jar target/kernel-keymanager-service-*.jar
   ```

4. **Verify and Interact**
   Once the service is up and running, you can explore the APIs:
    - **Swagger UI**: Access the interactive API documentation at [http://localhost:8088/v1/keymanager/swagger-ui/index.html#/](http://localhost:8088/v1/keymanager/swagger-ui/index.html#/)
    - **Postman**: You can also import the collection and test the APIs using [Postman](https://www.postman.com/).

> **Note**: Keymanager relies on standard OAuth2/OIDC bearer token authentication. You may use MOSIP Auth Adaptor or any compatible OAuth2/OIDC provider to secure the REST APIs.

## Local Setup by building docker image
1. Pull the docker image from the docker hub:
   ```bash
   docker pull mosipid/kernel-keymanager-service:latest
   ```

2. Build the Docker image:
   ```bash
   cd kernel/kernel-keymanager-service
   docker build -t mosip/kernel-keymanager-service .
   ```
3. Run the Docker container:
   ```bash
   docker run -d --name keymanager-service \
     -p 8088:8088 \
     -e active_profile_env=local \
     mosip/kernel-keymanager-service
   ```

## Deployment
Scripts for deployment are available in the `deploy` directory.
### Pre-requisites
* Set KUBECONFIG variable to point to existing K8 cluster kubeconfig file:
    * ```
    export KUBECONFIG=~/.kube/<my-cluster.config>
    ```

### Install
  ```
    $ cd deploy
    $ ./install.sh
   ```
### Delete
  ```
    $ cd deploy
    $ ./delete.sh
   ```
### Restart
  ```
    $ cd deploy
    $ ./restart.sh
   ```

Refer to the `deploy` directory for more details.

## Upgrade

Upgrade scripts for the database are available in the `db_upgrade_scripts/mosip_keymgr` directory.

To upgrade the database:
1.  Navigate to `db_upgrade_scripts/mosip_keymgr`.
2.  Update the `upgrade.properties` file with the required configurations:
    *   `CURRENT_VERSION`: The current version of your database (e.g., `<current_version>`).
    *   `UPGRADE_VERSION`: The target version (e.g., `<target_version>`).
    *   `ACTION`: Set to `upgrade` (or `rollback`).
3.  Run the `upgrade.sh` script passing the properties file:
    ```bash
    ./upgrade.sh upgrade.properties
    ```

Specific SQL scripts for version upgrades (e.g., `<current_version>_to_<target_version>_upgrade.sql`) are located in the `sql` subdirectory.

## Documentation
- **API Documentation**: [API Documentation](https://mosip.github.io/documentation/1.2.0/kernel-keymanager-service.html)
- **Product Documentation**: [Key Manager Documentation](https://docs.mosip.io/1.2.0/modules/keymanager)

## Contribution & Community
We welcome contributions from everyone!

[Check here](https://docs.mosip.io/1.2.0/community/code-contributions) to learn how you can contribute code to this application.

If you have any questions or run into issues while trying out the application, feel free to post them in the [MOSIP Community](https://community.mosip.io/) — we’ll be happy to help you out.

[GitHub Issues](https://github.com/mosip/keymanager/issues)
