[![Maven Package upon a push](https://github.com/mosip/keymanager/actions/workflows/push_trigger.yml/badge.svg?branch=develop)](https://github.com/mosip/keymanager/actions/workflows/push_trigger.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?branch=develop&project=mosip_keymanager&metric=alert_status)](https://sonarcloud.io/dashboard?branch=develop&id=mosip_keymanager)

# Key Manager

## Overview
The Key Manager Service provides secure storage, provisioning and management of secret data. It provides all the cryptographic operations like encryption/decryption and digital signature/verification making one trust store for all partner trust path validation. It manages the lifecycle of encryption/decryption keys, including generation, distribution, administration, and deletion.

Reference: [Key Manager](https://docs.mosip.io/1.2.0/id-lifecycle-management/supporting-components/keymanager) for more details.

## Features
- **Cryptographic Operations**: Encryption, Decryption, Digital Signature, and Verification.
- **Key Lifecycle Management**: Generation, Rotation, Revocation, and Expiry of keys.
- **Trust Store**: Centralized trust store for partner trust path validation.
- **HSM Integration**: Supports Hardware Security Modules (HSM) like SoftHSM and CloudHSM for secure key storage.
- **Zero-Knowledge Encryption/Decryption**: Supports Zero-Knowledge encryption and decryption for data protection.
- **Key Hierarchy**: Manages Root, Module, and Base keys.

## Services
- **kernel-keymanager-service**: The core service that exposes APIs for key management operations.
- **keys-generator**: A utility/job for generating the initial set of keys for zk encryption/decryption.
- **keys-migrator**: A utility for migrating keys between different HSMs or databases.

## Local Setup
There are two ways to set up the Key Manager service locally:
1. [Local Deployment](#local-deployment) (Running the JAR file)
2. [Local Setup using Docker](#local-setup-using-docker-image)

## Pre-requisites
- JDK 21 or higher
- Maven 3.9.x
- PostgreSQL 10 or higher
- SoftHSM or a compatible HSM
- Docker (for Docker-based setup)

## Database Setup
Refer to [SQL scripts](https://github.com/mosip/keymanager/tree/develop/db_scripts)

## Configurations
The service configuration can be found in `kernel/kernel-keymanager-service/src/main/resources/application-local.properties`. Key configurations include:
- `mosip.kernel.keymanager.hsm.keystore-type`: Type of keystore (e.g., PKCS11, Offline).
- `keymanager_database_url`: Database connection URL.
- `keymanager_database_username`: Database username.
- `keymanager_database_password`: Database password.
- `mosip.kernel.keymanager.hsm.config-path`: Path to the HSM configuration file.

## Local Deployment
1. Build the project:
   ```bash
   cd kernel
   mvn clean install -DskipTests=true -Dmaven.javadoc.skip=true -Dgpg.skip=true
   ```
2. Run the service:
   ```bash
   cd kernel-keymanager-service
   java -jar target/kernel-keymanager-service-*.jar
   ```

## Local Setup using docker image
To run the service using an existing Docker image:
```bash
docker run -d --name keymanager-service \
  -p 8088:8088 \
  -e active_profile_env=local \
  mosip/kernel-keymanager-service:latest
```
*Note: Ensure you have the necessary environment variables and network configurations set up.*

## Local Setup by building docker image
1. Build the Docker image:
   ```bash
   cd kernel/kernel-keymanager-service
   docker build -t mosip/kernel-keymanager-service .
   ```
2. Run the Docker container:
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

Refer to the [deploy](https://github.com/mosip/keymanager/tree/develop/deploy) directory for more details.

## Upgrade
Upgrade scripts for the database are available in the [db_upgrade_scripts](https://github.com/mosip/keymanager/tree/develop/db_upgrade_scripts/mosip_keymgr) directory.

## Documentation
- **API Documentation**: [API Documentation](https://mosip.github.io/documentation/1.2.0/kernel-keymanager-service.html)
- **Product Documentation**: [Key Manager Documentation](https://docs.mosip.io/1.2.0/modules/keymanager)

## Contribution & Community
We welcome contributions from everyone!

[Check here](https://docs.mosip.io/1.2.0/community/code-contributions) to learn how you can contribute code to this application.

If you have any questions or run into issues while trying out the application, feel free to post them in the [MOSIP Community](https://community.mosip.io/) — we’ll be happy to help you out.

[Github Issues](https://github.com/mosip/keymanager/issues)
