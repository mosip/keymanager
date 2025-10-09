package io.mosip.kernel.keymanagerservice.test.helper;

import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.entity.KeyPolicy;
import io.mosip.kernel.keymanagerservice.entity.KeyStore;
import io.mosip.kernel.keymanagerservice.exception.InvalidApplicationIdException;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class KeymanagerDBHelperTest {

    @Autowired
    private KeymanagerDBHelper dbHelper;

    private LocalDateTime timestamp;
    private String testAlias;
    private String testAppId = "TEST_APP";
    private String testRefId = "TEST_REF";

    @Before
    public void setUp() {
        timestamp = DateUtils.getUTCCurrentDateTime();
        testAlias = UUID.randomUUID().toString();
    }

    @Test
    public void testStoreKeyInDBStore() {
        String masterAlias = testAlias;
        String certificateData = "-----BEGIN CERTIFICATE-----\nMIICertificateData\n-----END CERTIFICATE-----";
        String encryptedPrivateKey = "encryptedPrivateKeyData";

        dbHelper.storeKeyInDBStore(testAlias, masterAlias, certificateData, encryptedPrivateKey);

        Optional<KeyStore> result = dbHelper.getKeyStoreFromDB(testAlias);
        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(testAlias, result.get().getAlias());
        Assert.assertEquals(masterAlias, result.get().getMasterAlias());
    }

    @Test
    public void testGetKeyAliases() {
        String certThumbprint = "DED24BC711E7F77273591F9B1A9567199575607425D9182DA53826AAAD4F950E";
        String uniqueIdentifier = "C15AF8613AF647262E38E6200305EF0D2AAA7DAA";

        dbHelper.storeKeyInAlias(testAppId, timestamp.minusDays(1), testRefId, testAlias,
                timestamp.plusYears(1), certThumbprint, uniqueIdentifier);

        Map<String, List<KeyAlias>> result = dbHelper.getKeyAliases(testAppId, testRefId, timestamp);

        Assert.assertNotNull(result);
        Assert.assertTrue(result.containsKey("keyAlias"));
        Assert.assertTrue(result.containsKey("currentKeyAlias"));
        Assert.assertFalse(result.get("keyAlias").isEmpty());
    }

    @Test
    public void testGetExpiryPolicy() {
        LocalDateTime result = dbHelper.getExpiryPolicy("TEST", timestamp, List.of());
        Assert.assertEquals(timestamp.plusDays(1095), result);
    }

    @Test
    public void testGetKeyStoreFromDB() {
        String masterAlias = testAlias;
        String certificateData = "-----BEGIN CERTIFICATE-----\nTestCertData\n-----END CERTIFICATE-----";
        String encryptedPrivateKey = "testEncryptedKey";

        dbHelper.storeKeyInDBStore(testAlias, masterAlias, certificateData, encryptedPrivateKey);

        Optional<KeyStore> result = dbHelper.getKeyStoreFromDB(testAlias);

        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(testAlias, result.get().getAlias());
        Assert.assertEquals(certificateData, result.get().getCertificateData());
    }

    @Test
    public void testGetKeyStoreFromDBNotFound() {
        Optional<KeyStore> result = dbHelper.getKeyStoreFromDB("NON_EXISTENT_ALIAS");
        Assert.assertFalse(result.isPresent());
    }

    @Test
    public void testGetKeyPolicy() {
        Optional<KeyPolicy> result = dbHelper.getKeyPolicy("TEST");
        Assert.assertTrue(result.isPresent());
    }

    @Test
    public void testGetExpiryPolicyInvalidApplicationId() {
        InvalidApplicationIdException exception = assertThrows(InvalidApplicationIdException.class, () -> {
            dbHelper.getExpiryPolicy("INVALID_APP_ID", timestamp, List.of());
        });
        Assert.assertEquals("KER-KMS-002", exception.getErrorCode());
        Assert.assertEquals("KER-KMS-002 --> ApplicationId not found in Key Policy. Key/CSR generation not allowed.", exception.getMessage());
    }

    @Test
    public void testGetKeyPolicyFromCache() {
        Optional<KeyPolicy> result = dbHelper.getKeyPolicyFromCache("TEST");
        Assert.assertNotNull(result);
    }

    @Test
    public void testGetKeyPolicyInvalidApplicationId() {
        InvalidApplicationIdException exception = assertThrows(InvalidApplicationIdException.class, () -> {
            dbHelper.getKeyPolicy("INVALID_APP_ID");
        });
        Assert.assertEquals("KER-KMS-002", exception.getErrorCode());
        Assert.assertEquals("KER-KMS-002 --> ApplicationId not found in Key Policy. Key/CSR generation not allowed.", exception.getMessage());
    }

    @Test
    public void testGetKeyAliasWithThumbprint() {
        String certThumbprint = "DED24BC711E7F77273591F9B1A9567199575607425D9182DA53826AAAD4F950E";
        String uniqueIdentifier = "C15AF8613AF647262E38E6200305EF0D2AAA7DA8";
        String appIdRefIdKey = testAppId + "-" + testRefId;

        // Store key in alias first
        dbHelper.storeKeyInAlias(testAppId, timestamp, testRefId, testAlias,
                timestamp.plusYears(1), certThumbprint, uniqueIdentifier);

        // Store corresponding key in DB store
        String certificateData = "-----BEGIN CERTIFICATE-----\nThumbprintTestCert\n-----END CERTIFICATE-----";
        dbHelper.storeKeyInDBStore(testAlias, testAlias, certificateData, "encryptedKey");

        KeyStore result = dbHelper.getKeyAlias(certThumbprint, appIdRefIdKey, testAppId, testRefId);

        Assert.assertNotNull(result);
        Assert.assertEquals(testAlias, result.getAlias());
    }

    @Test
    public void testGetKeyAliasThumbprintNotFound() {
        String nonExistentThumbprint = "NON2EXISTENTF77273591F9B1A9567199575607425D9182DA53826AAAD4F950E";
        String appIdRefIdKey = testAppId + "-" + testRefId;

        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            dbHelper.getKeyAlias(nonExistentThumbprint, appIdRefIdKey, testAppId, testRefId);
        });
        Assert.assertEquals("KER-KMS-025", exception.getErrorCode());
        Assert.assertEquals("KER-KMS-025 --> Key Not found for the thumbprint prepended in encrypted data.", exception.getMessage());
    }
}
