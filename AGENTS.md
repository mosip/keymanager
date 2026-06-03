# MOSIP Key Manager — AGENTS.md

## Project Overview

Central cryptographic key management service for the MOSIP identity platform. Provides key lifecycle management, encryption/decryption, digital signatures, HSM integration, and partner certificate trust management. All MOSIP modules (Registration, IDA, Packet Manager, Datashare) rely on this service for crypto operations.

Docs: https://docs.mosip.io/1.2.0/id-lifecycle-management

---

## Repository Structure

```
keymanager/
├── kernel/                         # Maven parent + 3 modules
│   ├── pom.xml                     # Parent POM (io.mosip.kernel:keymanager-parent)
│   ├── kernel-keymanager-service/  # Core REST service (Spring Boot)
│   ├── keys-generator/             # One-shot key bootstrap utility
│   └── keys-migrator/              # HSM-to-HSM key migration utility
├── helm/
│   ├── keymanager/                 # Service chart
│   ├── keygen/                     # Key generator job chart
│   ├── key-migration-utility/      # Migrator chart
│   └── softhsm/                    # SoftHSM (non-prod HSM simulation)
├── db_scripts/mosip_keymgr/        # PostgreSQL schema (DDL, DML, grants)
├── db_upgrade_scripts/             # Versioned migration SQL (upgrade + rollback)
└── deploy/                         # Kubernetes install scripts + values overrides
```

---

## Build & Test

```bash
# Build all modules
mvn clean install -f kernel/pom.xml

# Build only the service (skip tests)
mvn clean install -pl kernel/kernel-keymanager-service -DskipTests -f kernel/pom.xml

# Run tests (uses H2 in-memory DB — no PostgreSQL needed)
mvn test -pl kernel/kernel-keymanager-service -f kernel/pom.xml

# Build Docker image (run from kernel/kernel-keymanager-service/)
docker build -t mosipqa/kernel-keymanager-service:<tag> .
```

Tests use H2 in-memory DB via `src/test/resources/schema.sql` + `data.sql`. No external services needed for unit/integration tests.

---

## Key Technology Stack

- **Java 21**, **Spring Boot 3.2.3**, **Maven 3.9.x**
- **Database**: PostgreSQL (prod), H2 (test) via Spring Data JPA
- **HSM**: PKCS#11 abstraction (`kernel.keymanager.hsm`), supports SoftHSM / Luna / Thales
- **Crypto libs**: BouncyCastle 1.78.1 (`bcprov-jdk18on`, `bcpkix-jdk18on`), Nimbus JOSE+JWT 9.37.2, jose4j 0.9.6
- **Other**: CBOR (1.19), Argon2 (2.11), JNA (5.13.0), cache2k (2.4.1), TSS.Java (0.3.0)
- **API docs**: springdoc-openapi 2.6.0 (accessible at `/v1/keymanager/swagger-ui.html`)

---

## Module Versions (current develop)

| Artifact | Version          |
|----------|------------------|
| `keymanager-parent` | `1.5.0-SNAPSHOT` |
| `kernel-keymanager-service` | `1.5.0-SNAPSHOT` |
| `keys-generator` | `1.5.0-SNAPSHOT` |
| `keys-migrator` | `1.5.0-SNAPSHOT` |
| `kernel-bom` / `kernel-core` deps | `1.4.0-SNAPSHOT` |
| Helm chart versions | `0.0.1-develop`  |

---

## Java Package Structure

All packages live under `io.mosip.kernel.*`:

| Package | Purpose |
|---------|---------|
| `keymanagerservice` | Core key management REST API, DB entities, policies |
| `cryptomanager` | Encrypt/decrypt, JWT, Argon2, symmetric ops |
| `signature` | Digital signature generation & verification (COSE, JWS) |
| `partnercertservice` | Partner/CA certificate upload, trust path validation |
| `zkcryptoservice` | Zero-knowledge AES-256 encryption |
| `tokenidgenerator` | Token ID generation |
| `clientcrypto` | Client-side crypto facade (Android/local) |
| `keymanager.hsm` | PKCS#11 HSM abstraction layer (`PKCS11KeyStoreImpl`) |
| `keymigrate` | Key migration logic |
| `crypto.jce` | JCE core crypto operations |
| `keygenerator` | BouncyCastle key-pair generation utilities |

### Key Files to Know

| File | What it does |
|------|-------------|
| `KeymanagerServiceImpl.java` | Core key lifecycle: generate, fetch, rotate, revoke |
| `CryptomanagerServiceImpl.java` | Encryption/decryption entry point |
| `PKCS11KeyStoreImpl.java` | HSM integration via PKCS#11 |
| `PartnerCertificateManagerServiceImpl.java` | Upload/validate partner certs |
| `KeymanagerController.java` | REST endpoints |
| `KeymanagerDBHelper.java` | DB queries for key alias / key store tables |
| `configure_start.sh` | Docker entrypoint: downloads HSM client, configures Spring |

---

## Key Hierarchy (MOSIP Design)

```
Root Key (HSM, 5yr)
  └── Module Key (HSM, 3yr) — one per application/module
        └── Base Key (DB encrypted, 2yr) — one per app+ref_id pair
```

- Root and Module keys live on the **HSM only**
- Base keys are stored encrypted in the `key_store` DB table
- Key aliases are indexed in `key_alias` table (app_id + ref_id + expiry)
- `cert_thumbprint` in `key_alias` identifies which key encrypted a packet

---

## Database Schema (`mosip_keymgr`)

Main tables:
- `key_alias` — key metadata index (app_id, ref_id, expiry, status, cert_thumbprint)
- `key_store` — encrypted private key material (Base keys)
- `key_policy_def` — per-module key validity periods
- `ca_cert_store` — trusted CA certificates (includes `ca_cert_type` column)
- `partner_cert_store` — partner certificates
- `data_encrypt_keystore` — data encryption keys
- `licensekey_list`, `licensekey_permission`, `tsp_licensekey_map` — license key mgmt

DB scripts: `db_scripts/mosip_keymgr/`
Migrations: `db_upgrade_scripts/mosip_keymgr/sql/` (versioned `X_to_Y_upgrade.sql` + rollback)

---

## HSM Configuration

Key Spring properties (set via config server or env):
```properties
mosip.kernel.keymanager.hsm.keystore-type=PKCS11        # or JCE, OFFLINE, etc.
mosip.kernel.keymanager.hsm.config-path=/etc/softhsm2.conf
mosip.kernel.keymanager.hsm.keystore-pass=<pin>
```

For local dev, SoftHSM is used (Helm chart: `helm/softhsm`). In production, a hardware HSM is configured via `configure_start.sh` which downloads the HSM client from Artifactory.

Service port: **8088**. Actuator/management port: **9010**.

---

## Helm Charts

All charts use `0.0.1-develop` version on develop branch. Do **not** change Chart.yaml `version` when working on develop — it's bumped only at release time.

Key `values.yaml` production settings (keymanager chart):
```yaml
resources:
  limits: { cpu: 2000m, memory: 8000Mi }
  requests: { cpu: 1000m, memory: 4000Mi }
additionalResources:
  javaOpts: "-XX:+UseZGC -XX:+ZGenerational -XX:ZCollectionInterval=5 -Xms4000m -Xmx5400m ..."
```

`helm/softhsm/values.yaml` image: `mosipqa/softhsm` (QA/dev registry — **not** `mosipid/softhsm`).

---

## CI/CD (GitHub Actions)

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `push-trigger.yml` | Push to `develop`/`release-*`/`master`, PRs | Maven build + publish via Kattu |
| `db-test.yml` | Changes to `db_scripts/` | PostgreSQL schema validation |
| `chart-lint-publish.yml` | PR / release publish | Helm chart lint + publish to chart repo |
| `clear-artifacts.yml` | Manual | Clean up old artifacts |

---

## Development Conventions

- **Branch naming**: `develop` (main dev), `release-1.x.x` (release lines), feature branches
- **Merge strategy**: Release → develop merges take release code by default; keep develop's pom versions, helm chart versions (`0.0.1-develop`), and softhsm image (`mosipqa`)
- **Test conventions**: Tests use H2 + `@SpringBootTest`; test resource files in `src/test/resources/`
- **No `mockito-inline` in prod scope** — test-scoped only
- **Java path convention**: test util packages use lowercase (`util/`, not `Util/`)
- **DB script naming**: `X_to_Y_upgrade.sql` and `X_to_Y_rollback.sql` in `db_upgrade_scripts/mosip_keymgr/sql/`

---

## Cross-Repo Dependencies

When bumping `kernel-keymanager-service` version, update references in:
- `mosip/id-authentication` — depends on `kernel-keymanager-service`
- `mosip/registration` / `mosip/registration-processor`
- `mosip/commons` — kernel-bom may carry keymanager version

When bumping `kernel-bom` / `kernel-core` dependency versions, coordinate with the `mosip/commons` release.
