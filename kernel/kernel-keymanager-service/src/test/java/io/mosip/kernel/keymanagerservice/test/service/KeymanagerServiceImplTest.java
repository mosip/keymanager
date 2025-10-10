package io.mosip.kernel.keymanagerservice.test.service;

import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.dto.*;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.exception.NoUniqueAliasException;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.repository.KeyPolicyRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.keymanagerservice.validator.ECKeyPairGenRequestValidator;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class KeymanagerServiceImplTest {

    @Autowired
    private KeymanagerService service;

    @Autowired
    private KeymanagerDBHelper dbHelper;

    @Autowired
    private ECKeyPairGenRequestValidator ecKeyPairGenRequestValidator;

    @Autowired
    private KeyPolicyRepository keyPolicyRepository;

    @Autowired
    private io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository keyAliasRepository;

    @Autowired
    private io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository keyStoreRepository;

    @Autowired
    private KeymanagerUtil keymanagerUtil;

    KeyPairGenerateResponseDto generateMasterKey;

    String timestampStr = DateUtils.getUTCCurrentDateTime().toString();

    @Before
    public void setUp() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        generateMasterKey = service.generateMasterKey("CSR", keyPairGenRequestDto);
    }

    @After
    public void tearDown() {
        keyStoreRepository.deleteAll();
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testGenerateMaserKey() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keyPairGenRequestDto.setForce(true);
        KeyPairGenerateResponseDto result = service.generateMasterKey("CSR", keyPairGenRequestDto);
        Assert.assertNotNull(result);

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keyPairGenRequestDto.setForce(false);
        KeyPairGenerateResponseDto result2 = service.generateMasterKey("CERTIFICATE", keyPairGenRequestDto);
        Assert.assertNotNull(result2);
    }

    @Test
    public void testGenerateMasterKeyThrowKeymanagerServiceException() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("BASE");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("BASE");
        keyPairGenRequestDto.setReferenceId("test");
        keyPairGenRequestDto.setForce(null);
        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            service.generateMasterKey("CSR", keyPairGenRequestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.REFERENCE_ID_NOT_SUPPORTED.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-010 --> Reference Id Not Supported for the Application ID.", exception.getMessage());

        keyPairGenRequestDto.setReferenceId(null);
        KeymanagerServiceException invalidException = assertThrows(KeymanagerServiceException.class, () -> {
            service.generateMasterKey("", keyPairGenRequestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(), invalidException.getErrorCode());
        Assert.assertEquals("KER-KMS-005 --> Invalid request", invalidException.getMessage());
    }

    @Test
    public void testGenerateMasterKeyThrowNoUniqueKeyAliasException() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "F367FDFB62F959DE8F38E24ACE65EED053F5C7CC4E8AB496DF1DA515D3173988", "A8402FCA390FA3DB5B8EDDD06CE9A008C3CBB752");
        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "A8ECF08AB926EF26DB80E6C1B0DD4E9B9FA8E43A2BEC724F05C1B500D9FED5C2", "AA05CFE5D1AA1B814ABDDFF5FCDF6346CB30E8F6");
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keyPairGenRequestDto.setForce(false);
        NoUniqueAliasException exception = assertThrows(NoUniqueAliasException.class, () -> {
            service.generateMasterKey("CSR", keyPairGenRequestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-003 --> No unique alias is found", exception.getMessage());
    }

    @Test
    public void testGetCertificateFromHSM() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto certificate = service.getCertificate("TEST", Optional.of(""));
        Assert.assertEquals(certificate.getCertificate(), service.getCertificate("TEST", Optional.of("")).getCertificate());

        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        service.generateECSignKey("CERTIFICATE", keyPairGenRequestDto);
        certificate = service.getCertificate("TEST", Optional.of("EC_SECP256R1_SIGN"));
        Assert.assertEquals(certificate.getCertificate(), service.getCertificate("TEST", Optional.of("EC_SECP256R1_SIGN")).getCertificate());

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        service.generateMasterKey("CERTIFICATE", keyPairGenRequestDto);
        KeyPairGenerateResponseDto certificate2 = service.getCertificate("KERNEL", Optional.of("SIGN"));
        Assert.assertEquals(certificate2.getCertificate(), service.getCertificate("KERNEL", Optional.of("SIGN")).getCertificate());

        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        service.generateECSignKey("CSR", keyPairGenRequestDto);
        certificate2 = service.getCertificate("TEST", Optional.of("ED25519_SIGN"));
        Assert.assertEquals(certificate2.getCertificate(), service.getCertificate("TEST", Optional.of("ED25519_SIGN")).getCertificate());
    }

    @Test
    public void testGetCertificateFromDBStore() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        CSRGenerateRequestDto csrGenerateRequestDto = new CSRGenerateRequestDto();
        csrGenerateRequestDto.setApplicationId("TEST");
        csrGenerateRequestDto.setReferenceId("dbCert");
        service.generateCSR(csrGenerateRequestDto);

        KeyPairGenerateResponseDto certificate = service.getCertificate("TEST", Optional.of("dbCert"));
        Assert.assertEquals(certificate.getCertificate(), service.getCertificate("TEST", Optional.of("dbCert")).getCertificate());
    }

    @Test(expected = KeymanagerServiceException.class)
    public void testGetCertificateKeymanagerServiceException() {
        service.getCertificate("ID_REPO", Optional.of(""));
    }

    @Test
    public void testGetCertificateNoUniqueAliasException() {
        LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "F367FDFB62F959DE8F38E24ACE65EED053F5C7CC4E8AB496DF1DA515D3173988", "A8402FCA390FA3DB5B8EDDD06CE9A008C3CBB75A");
        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "A8ECF08AB926EF26DB80E6C1B0DD4E9B9FA8E43A2BEC724F05C1B500D9FED5C2", "AA05CFE5D1AA1B814ABDDFF5FCDF6346CB30E8F1");
        NoUniqueAliasException exception = assertThrows(NoUniqueAliasException.class, () -> {
            service.getCertificate("TEST", Optional.of(""));
        });
        Assert.assertEquals(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-003 --> No unique alias is found", exception.getMessage());

        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "test", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "F367FDFB62F959DE8F38E24ACE65EED053F5C7CC4E8AB496DF1DA515D3173988", "A8402FCA390FA3DB5B8EDDD06CE9A008C3CBB75B");
        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "test", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "A8ECF08AB926EF26DB80E6C1B0DD4E9B9FA8E43A2BEC724F05C1B500D9FED5C2", "AA05CFE5D1AA1B814ABDDFF5FCDF6346CB30E8F2");
        NoUniqueAliasException exception1 = assertThrows(NoUniqueAliasException.class, () -> {
            service.getCertificate("TEST", Optional.of("test"));
        });
        Assert.assertEquals(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(), exception1.getErrorCode());
        Assert.assertEquals("KER-KMS-003 --> No unique alias is found", exception1.getMessage());

        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "abc", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "F367FDFB62F959DE8F38E24ACE65EED053F5C7CC4E8AB496DF1DA515D3173988", "A8402FCA390FA3DB5B8EDDD06CE9A008C3CBB75C");
        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "abc", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "F367FDFB62F959DE8F38E24ACE65EED053F5C7CC4E8AB496DF1DA515D3173988", "A8402FCA390FA3DB5B8EDDD06CE9A008C3CBC86C");
        NoUniqueAliasException exception2 = assertThrows(NoUniqueAliasException.class, () -> {
            service.getCertificate("TEST", Optional.of("abc"));
        });
        Assert.assertEquals(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(), exception2.getErrorCode());
        Assert.assertEquals("KER-KMS-003 --> No unique alias is found", exception2.getMessage());
    }

    @Test
    public void testGetCrtificateKeymanagerServiceException() {
        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            service.getCertificate("ROOT", Optional.of("abcd"));
        });
        Assert.assertEquals(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-016 --> Not allowed to generate new key pair for other domains or not allowed to generate base key. (Root Key)", exception.getMessage());

        KeymanagerServiceException exception1 = assertThrows(KeymanagerServiceException.class, () -> {
            service.getCertificate("KERNEL", Optional.of("abcd"));
        });
        Assert.assertEquals(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorCode(), exception1.getErrorCode());
        Assert.assertEquals("KER-KMS-016 --> Not allowed to generate new key pair for other domains or not allowed to generate base key. (Kernel App Id)", exception1.getMessage());

        KeymanagerServiceException exception2 = assertThrows(KeymanagerServiceException.class, () -> {
            service.getCertificate("PARTNER", Optional.of("abcd"));
        });
        Assert.assertEquals(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorCode(), exception2.getErrorCode());
        Assert.assertEquals("KER-KMS-016 --> Not allowed to generate new key pair for other domains or not allowed to generate base key. (Partner App Id)", exception2.getMessage());
    }

    @Test
    public void testGenerateCSR() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        CSRGenerateRequestDto requestDto = new CSRGenerateRequestDto();

        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("");
        KeyPairGenerateResponseDto result1 = service.generateCSR(requestDto);
        Assert.assertEquals(result1.getCertificate(), service.generateCSR(requestDto).getCertificate());

        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("csr");
        KeyPairGenerateResponseDto result = service.generateCSR(requestDto);
        Assert.assertEquals(result.getCertificate(), service.generateCSR(requestDto).getCertificate());

        requestDto.setApplicationId("KERNEL");
        requestDto.setReferenceId("SIGN");
        KeyPairGenerateResponseDto result2 = service.generateCSR(requestDto);
        Assert.assertEquals(result2.getCertificate(), service.generateCSR(requestDto).getCertificate());
    }

    @Test
    public void testUploadCertificate() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        UploadCertificateRequestDto requestDto = new UploadCertificateRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("");
        KeyPairGenerateResponseDto certificate = service.getCertificate("TEST", Optional.of(""));
        requestDto.setCertificateData(certificate.getCertificate());
        UploadCertificateResponseDto result = service.uploadCertificate(requestDto);
        Assert.assertNotNull(result);
    }

    @Test
    public void testUploadCertificateKeymanagerServiceException() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        CSRGenerateRequestDto csrGenerateRequestDto = new CSRGenerateRequestDto();
        csrGenerateRequestDto.setApplicationId("TEST");
        csrGenerateRequestDto.setReferenceId("test");
        service.generateCSR(csrGenerateRequestDto);

        UploadCertificateRequestDto requestDto = new UploadCertificateRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("");
        requestDto.setCertificateData(null);
        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            service.uploadCertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-005 --> Invalid request", exception.getMessage());

        KeyPairGenerateResponseDto certificate = service.getCertificate("TEST", Optional.of(""));
        requestDto.setCertificateData(certificate.getCertificate());
        requestDto.setReferenceId("test");
        KeymanagerServiceException exception1 = assertThrows(KeymanagerServiceException.class, () -> {
            service.uploadCertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.KEY_NOT_MATCHING.getErrorCode(), exception1.getErrorCode());
        Assert.assertEquals("KER-KMS-014 --> Certificate Key Not Matching with stored Key.", exception1.getMessage());
    }

    @Test
    public void testUploadOtherDomainCertificate() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);
        UploadCertificateRequestDto requestDto = new UploadCertificateRequestDto();
        requestDto.setApplicationId("PARTNER");
        requestDto.setReferenceId("TESTING");
        KeyPairGenerateResponseDto certificate = service.getCertificate("TEST", Optional.of(""));
        requestDto.setCertificateData(certificate.getCertificate());
        UploadCertificateResponseDto result = service.uploadOtherDomainCertificate(requestDto);
        Assert.assertEquals("Upload Success", result.getStatus());

        requestDto.setApplicationId("PARTNER");
        requestDto.setReferenceId("TESTING");
        requestDto.setCertificateData(certificate.getCertificate());
        KeymanagerServiceException exception3 = assertThrows(KeymanagerServiceException.class, () -> {
            service.uploadOtherDomainCertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.CERTIFICATE_ALREADY_EXIST.getErrorCode(), exception3.getErrorCode());
        Assert.assertEquals("KER-KMS-035 --> Certificate Already Exist, not allowed to upload same certificate again", exception3.getMessage());

        KeyPairGenerateResponseDto certificate1 = service.getCertificate("TEST", Optional.of("test"));
        requestDto.setCertificateData(certificate1.getCertificate());
        UploadCertificateResponseDto result1 = service.uploadOtherDomainCertificate(requestDto);
        Assert.assertEquals("Upload Success", result1.getStatus() );
    }

    @Test
    public void testUploadOtherDomainCertificateKeymanagerServiceException() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ID_REPO");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        UploadCertificateRequestDto requestDto = new UploadCertificateRequestDto();
        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            service.uploadOtherDomainCertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-005 --> Invalid request", exception.getMessage());

        requestDto.setApplicationId("KERNEL");
        requestDto.setReferenceId("SIGN");
        requestDto.setCertificateData("BEGIN CERTIFICATE---END CERTIFICATE");
        KeymanagerServiceException exception1 = assertThrows(KeymanagerServiceException.class, () -> {
            service.uploadOtherDomainCertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.SIGN_APP_ID_REFERENCEID_NOT_ALLOWED.getErrorCode(), exception1.getErrorCode());
        Assert.assertEquals("KER-KMS-031 --> Application Id with KERNEL & Reference Id with Sign not allowed to upload Partner certificate.", exception1.getMessage());

        requestDto.setReferenceId("EC_SECP256R1_SIGN");
        KeymanagerServiceException exception2 = assertThrows(KeymanagerServiceException.class, () -> {
            service.uploadOtherDomainCertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.EC_SIGN_REFERENCE_ID_NOT_SUPPORTED.getErrorCode(), exception2.getErrorCode());
        Assert.assertEquals("KER-KMS-030 --> EC Sign Reference Id Not Supported for the Application ID.", exception2.getMessage());

        LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
        dbHelper.storeKeyInAlias("PARTNER", timestamp.minusYears(2), "test", UUID.randomUUID().toString(), timestamp.minusDays(1),
                "A8ECF08AB926EF26DB80E6C1B0DD4E9B9FA8E43A2BEC724F05C1B500D9FED5C2", "AA05CFE5D1AA1B814ABDDFF5FCDF6346CB30E8F6");
        requestDto.setApplicationId("PARTNER");
        requestDto.setReferenceId("test");
        KeyPairGenerateResponseDto certificate = service.getCertificate("ID_REPO", Optional.of(""));
        requestDto.setCertificateData(certificate.getCertificate());
        KeymanagerServiceException exception3 = assertThrows(KeymanagerServiceException.class, () -> {
            service.uploadOtherDomainCertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.VALID_KEY_ALREADY_EXIST.getErrorCode(), exception3.getErrorCode());
        Assert.assertEquals("KER-KMS-032 --> Valid Key already Exist, not allowed to upload another Certificate.", exception3.getMessage());

        dbHelper.storeKeyInAlias("PARTNER", timestamp.minusDays(1), "test", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "A8ECF08AB926EF26DB80E6C1B0DD4E9B9FA8E43A2BEC724F05C1B500D9FED5C2", "AA05CFE5D1AA1B814ABDDFF5FCDF6346CB30E8FA");
        requestDto.setApplicationId("PARTNER");
        requestDto.setReferenceId("test");
        KeyPairGenerateResponseDto certificate1 = service.getCertificate("TEST", Optional.of(""));
        requestDto.setCertificateData(certificate1.getCertificate());
        KeymanagerServiceException exception4 = assertThrows(KeymanagerServiceException.class, () -> {
            service.uploadOtherDomainCertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.OTHER_DOMAIN_VALID_KEY_NOT_EXIST.getErrorCode(), exception4.getErrorCode());
        Assert.assertEquals("KER-KMS-033 --> Other Domain Valid key not available, Upload other domain valid Key certificate.", exception4.getMessage());

    }

    @Test
    public void testUploadOtherDomainCertificateNoUniqueKeyException() {
        LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
        dbHelper.storeKeyInAlias("PARTNER", timestamp.minusDays(1), "test", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "F367FDFB62F959DE8F38E24ACE65EED053F5C7CC4E8AB496DF1DA515D3173988", "A8402FCA390FA3DB5B8EDDD06CE9A008C3CBB752");
        dbHelper.storeKeyInAlias("PARTNER", timestamp.minusDays(1), "test", UUID.randomUUID().toString(), timestamp.plusYears(3),
                "A8ECF08AB926EF26DB80E6C1B0DD4E9B9FA8E43A2BEC724F05C1B500D9FED5C2", "AA05CFE5D1AA1B814ABDDFF5FCDF6346CB30E8F6");

        UploadCertificateRequestDto requestDto = new UploadCertificateRequestDto();
        requestDto.setApplicationId("PARTNER");
        requestDto.setReferenceId("test");
        requestDto.setCertificateData("BEGIN CERTIFICATE---END CERTIFICATE");
        NoUniqueAliasException exception = assertThrows(NoUniqueAliasException.class, () -> {
            service.uploadOtherDomainCertificate(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-003 --> No unique alias is found", exception.getMessage());
    }

    @Test
    public void testGenerateSymmetricKey() {
        SymmetricKeyGenerateRequestDto requestDto = new SymmetricKeyGenerateRequestDto();
        requestDto.setApplicationId("BASE");
        requestDto.setReferenceId("symmetricKeyTest");
        requestDto.setForce(false);
        SymmetricKeyGenerateResponseDto result = service.generateSymmetricKey(requestDto);
        Assert.assertEquals("Generation Success", result.getStatus());

        requestDto.setForce(true);
        SymmetricKeyGenerateResponseDto result1 = service.generateSymmetricKey(requestDto);
        Assert.assertEquals("Generation Success", result1.getStatus());

        requestDto.setForce(false);
        SymmetricKeyGenerateResponseDto result2 = service.generateSymmetricKey(requestDto);
        Assert.assertEquals("Key Exists.", result2.getStatus());
    }

    @Test
    public void testGenerateSymmetricKeyKeymanagerServiceException() {
        SymmetricKeyGenerateRequestDto requestDto = new SymmetricKeyGenerateRequestDto();
        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            service.generateSymmetricKey(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-005 --> Invalid request", exception.getMessage());
    }

    @Test
    public void testGenerateSymmetricKeyNoUniqueKeyException() {
        LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "abc", UUID.randomUUID().toString(), timestamp.plusYears(3),
                null, null);
        dbHelper.storeKeyInAlias("TEST", timestamp.minusDays(1), "abc", UUID.randomUUID().toString(), timestamp.plusYears(3),
                null, null);

        SymmetricKeyGenerateRequestDto requestDto = new SymmetricKeyGenerateRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("abc");
        NoUniqueAliasException exception = assertThrows(NoUniqueAliasException.class, () -> {
            service.generateSymmetricKey(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-003 --> No unique alias is found", exception.getMessage());
    }

    @Test
    public void testRevokeKey() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        CSRGenerateRequestDto csrGenerateRequestDto = new CSRGenerateRequestDto();
        csrGenerateRequestDto.setApplicationId("PMS");
        csrGenerateRequestDto.setReferenceId("revoke");
        service.generateCSR(csrGenerateRequestDto);

        RevokeKeyRequestDto requestDto = new RevokeKeyRequestDto();
        requestDto.setApplicationId("PMS");
        requestDto.setReferenceId("revoke");
        requestDto.setDisableAutoGen(true);

        RevokeKeyResponseDto result = service.revokeKey(requestDto);
        Assert.assertNotNull(result);
    }

    @Test
    public void testRevokeKeyKeymanagerServiceException() {
        RevokeKeyRequestDto requestDto = new RevokeKeyRequestDto();
        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            service.revokeKey(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-005 --> Invalid request", exception.getMessage());

        requestDto.setApplicationId("KERNEL");
        requestDto.setReferenceId("SIGN");
        KeymanagerServiceException exception1 = assertThrows(KeymanagerServiceException.class, () -> {
            service.revokeKey(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.REVOKE_NOT_ALLOWED.getErrorCode(), exception1.getErrorCode());
        Assert.assertEquals("KER-KMS-021 --> Key Revocation not allowed.", exception1.getMessage());
    }

    @Test
    public void testRevokeKeyUniqueKeyException() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        CSRGenerateRequestDto csrGenerateRequestDto = new CSRGenerateRequestDto();
        csrGenerateRequestDto.setApplicationId("TEST");
        csrGenerateRequestDto.setReferenceId("revoke");
        service.generateCSR(csrGenerateRequestDto);

        RevokeKeyRequestDto requestDto = new RevokeKeyRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("revoke");
        requestDto.setDisableAutoGen(false);

        RevokeKeyResponseDto result = service.revokeKey(requestDto);
        Assert.assertNotNull(result);

        NoUniqueAliasException exception = assertThrows(NoUniqueAliasException.class, () -> {
            service.revokeKey(requestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-003 --> No unique alias is found", exception.getMessage());
    }

    @Test
    public void testGetAllCertificates() {
        AllCertificatesDataResponseDto result = service.getAllCertificates("REGISTRATION", Optional.of("test"));
        Assert.assertNotNull(result);

        AllCertificatesDataResponseDto result1 = service.getAllCertificates("REGISTRATION", Optional.of(""));
        Assert.assertNotNull(result1);

        AllCertificatesDataResponseDto result2 = service.getAllCertificates("KERNEL", Optional.of("SIGN"));
        Assert.assertNotNull(result2);

        result = service.getAllCertificates("REGISTRATION", Optional.of("EC_SECP256R1_SIGN"));
        Assert.assertNotNull(result);

        result1 = service.getAllCertificates("REGISTRATION", Optional.of("ED25519_SIGN"));
        Assert.assertNotNull(result1);
    }

    @Test
    public void testGenerateECSignKey() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("EC_SECP256K1_SIGN");
        KeyPairGenerateResponseDto result = service.generateECSignKey("CSR", keyPairGenRequestDto);
        Assert.assertNotNull(result);
    }

    @Test
    public void testGetSignPublicKey() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PRE_REGISTRATION");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("PRE_REGISTRATION");
        keyPairGenRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        service.generateECSignKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("PRE_REGISTRATION");
        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        service.generateECSignKey("CERTIFICATE", keyPairGenRequestDto);

        PublicKeyResponse<String> result = service.getSignPublicKey("PRE_REGISTRATION", timestampStr, Optional.of(""));
        PublicKeyResponse<String> expected = service.getSignPublicKey("PRE_REGISTRATION", timestampStr, Optional.of(""));
        Assert.assertEquals(result.getPublicKey(), expected.getPublicKey());

        result = service.getSignPublicKey("KERNEL", timestampStr, Optional.of("SIGN"));
        Assert.assertNotNull(result);

        result = service.getSignPublicKey("PRE_REGISTRATION", timestampStr, Optional.of("EC_SECP256R1_SIGN"));
        Assert.assertNotNull(result);

        result = service.getSignPublicKey("PRE_REGISTRATION", timestampStr, Optional.of("ED25519_SIGN"));
        Assert.assertNotNull(result);
    }

    @Test
    public void testGetSignPublicKeyKeymanagerServiceException() {
        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            service.getSignPublicKey("TEST", timestampStr, Optional.of("signKey"));
        });
        Assert.assertEquals(KeymanagerErrorConstant.NOT_VALID_SIGNATURE_KEY.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-020 --> Signing operation not allowed for the provided application id & reference id.", exception.getMessage());

        exception = assertThrows(KeymanagerServiceException.class, () -> {
            service.getSignPublicKey("COMPLIANCE_TOOLKIT", timestampStr, Optional.of(""));
        });
        Assert.assertEquals(KeymanagerErrorConstant.KEY_GENERATION_NOT_DONE.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-012 --> Key Generation Process is not completed.", exception.getMessage());
    }

    @Test
    public void testGetSignPublicKeyUniqueKeyException() {
        LocalDateTime timestamp1 = DateUtils.getUTCCurrentDateTime();
        dbHelper.storeKeyInAlias("TEST", timestamp1.minusDays(1), "", UUID.randomUUID().toString(), timestamp1.plusYears(3),
                "F367FDFB62F959DE8F38E24ACE65EED053F5C7CC4E8AB496DF1DA515D3173988", "A8402FCA390FA3DB5B8EDDD06CE9A008C3CBB752");
        dbHelper.storeKeyInAlias("TEST", timestamp1.minusDays(1), "", UUID.randomUUID().toString(), timestamp1.plusYears(3),
                "A8ECF08AB926EF26DB80E6C1B0DD4E9B9FA8E43A2BEC724F05C1B500D9FED5C2", "AA05CFE5D1AA1B814ABDDFF5FCDF6346CB30E8F6");
        NoUniqueAliasException exception = assertThrows(NoUniqueAliasException.class, () -> {
            service.getSignPublicKey("TEST", timestampStr, Optional.of(""));
        });
        Assert.assertEquals(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-003 --> No unique alias is found", exception.getMessage());
    }

    @Test
    public void testGetSignatureCertificate() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ID_REPO");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("ID_REPO");
        keyPairGenRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        service.generateECSignKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("ID_REPO");
        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        service.generateECSignKey("CERTIFICATE", keyPairGenRequestDto);

        SignatureCertificate result = service.getSignatureCertificate("ID_REPO", Optional.of(""), timestampStr);
        Assert.assertNotNull(result);

        result = service.getSignatureCertificate("KERNEL", Optional.of("SIGN"), timestampStr);
        Assert.assertNotNull(result);

        result = service.getSignatureCertificate("ID_REPO", Optional.of("EC_SECP256R1_SIGN"), timestampStr);
        Assert.assertNotNull(result);

        result = service.getSignatureCertificate("ID_REPO", Optional.of("ED25519_SIGN"), timestampStr);
        Assert.assertNotNull(result);
    }

    @Test
    public void testGenerateMasterKeyWithSANValues() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keyPairGenRequestDto.setForce(true);
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        CSRGenerateRequestDto requestDto = new CSRGenerateRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("addSAN");
        KeyPairGenerateResponseDto result = service.generateCSR(requestDto);
        Assert.assertNotNull(result);
    }

    @Test
    public void testEcKeyValidator(){
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("REGISTRATION");
        keyPairGenRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        ecKeyPairGenRequestValidator.validate("CSR", keyPairGenRequestDto);
    }

    @Test
    public void testEcKeyValidatorException(){
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("REGISTRATION");
        keyPairGenRequestDto.setReferenceId("WRONG_REF_ID");
        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            ecKeyPairGenRequestValidator.validate("CSR", keyPairGenRequestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.EC_SIGN_REFERENCE_ID_NOT_SUPPORTED.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-030 --> EC Sign Reference Id Not Supported for the Application ID.", exception.getMessage());

        keyPairGenRequestDto.setReferenceId("ED25519_SIGN");
        exception = assertThrows(KeymanagerServiceException.class, () -> {
            ecKeyPairGenRequestValidator.validate("CERT", keyPairGenRequestDto);
        });
        Assert.assertEquals(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("KER-KMS-005 --> Invalid request Allowed values are CSR/CERTIFICATE.", exception.getMessage());
    }

    @Test
    public void testGenerateKeyPairInHSM() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("RESIDENT");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);
        
        // Update expiry column for the generated key
        updateKeyExpiry("RESIDENT", "", DateUtils.getUTCCurrentDateTime().minusHours(2), "FB59F8678D10E370C107442BD479D75ED1B2584A");
        KeyPairGenerateResponseDto result = service.getCertificate("RESIDENT", Optional.of(""));
        Assert.assertNotNull(result);

        keyPairGenRequestDto.setReferenceId("EC_SECP256R1_SIGN");
        service.generateECSignKey("CSR", keyPairGenRequestDto);
        updateKeyExpiry("RESIDENT", "EC_SECP256R1_SIGN", DateUtils.getUTCCurrentDateTime().minusHours(2), "FB59F8678D10E370C107442BD479D75ED1B258B1");
        result = service.generateECSignKey("CSR", keyPairGenRequestDto);
        Assert.assertNotNull(result);
    }
    
    private void updateKeyExpiry(String appId, String refId, LocalDateTime newExpiryTime, String uniqueId) {
        keyAliasRepository.findByApplicationIdAndReferenceId(appId, refId)
            .forEach(keyAlias -> {
                keyAlias.setKeyExpiryTime(newExpiryTime);
                keyAlias.setUniqueIdentifier(uniqueId);
                keyAliasRepository.save(keyAlias);
            });
    }

    @Test
    public void testGetCertificateTrustPath() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        service.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto certdetails = service.getCertificate("TEST", Optional.of(""));
        X509Certificate x509Certificate = (X509Certificate) keymanagerUtil.convertToCertificate(certdetails.getCertificate());
        keymanagerUtil.getCertificateTrustPath(x509Certificate);
    }
}
