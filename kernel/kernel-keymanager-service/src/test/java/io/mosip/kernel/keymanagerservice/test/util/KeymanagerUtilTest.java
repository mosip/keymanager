package io.mosip.kernel.keymanagerservice.test.util;

import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.keymanager.hsm.constant.KeymanagerErrorCode;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.signature.util.SignatureUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.core.keymanager.exception.KeystoreProcessingException;
import io.mosip.kernel.core.keymanager.model.CertificateEntry;
import io.mosip.kernel.core.util.DateUtils2;
import io.mosip.kernel.keymanager.hsm.util.CertificateUtility;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyPolicyRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class KeymanagerUtilTest {

    @MockBean
    private KeyAliasRepository keyAliasRepository;

    @MockBean
    private KeyPolicyRepository keyPolicyRepository;

    @MockBean
    private KeyStoreRepository keyStoreRepository;

    @Autowired
    private KeymanagerUtil keymanagerUtil;

    private KeyPair keyPairMaster;

    private KeyPair keyPair;

    private X509Certificate[] chain;
    @Autowired
    private SignatureUtil signatureUtil;

    @Before
    public void setupKey() throws NoSuchAlgorithmException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KeymanagerConstant.RSA);
        keyGen.initialize(2048);
        keyPairMaster = keyGen.generateKeyPair();
        keyPair = keyGen.generateKeyPair();
        X509Certificate x509Certificate = CertificateUtility.generateX509Certificate(keyPair.getPrivate(), keyPair.getPublic(), "mosip", "mosip", "mosip",
                "india", LocalDateTime.of(2010, 1, 1, 12, 00), LocalDateTime.of(2011, 1, 1, 12, 00), "SHA256withRSA", "BC");
        chain = new X509Certificate[1];
        chain[0] = x509Certificate;
    }

    @Test
    public void encryptdecryptPrivateKeyTest() {
        byte[] key = keymanagerUtil.encryptKey(keyPair.getPrivate(), keyPairMaster.getPublic());
        assertThat(key, isA(byte[].class));
        assertThat(keymanagerUtil.decryptKey(key, keyPairMaster.getPrivate(), keyPairMaster.getPublic()), isA(byte[].class));
    }

    @Test(expected = KeystoreProcessingException.class)
    public void isCertificateValidExceptionTest() {
        CertificateEntry<X509Certificate, PrivateKey> certificateEntry = new CertificateEntry<X509Certificate, PrivateKey>(
                chain, keyPair.getPrivate());
        keymanagerUtil.isCertificateValid(certificateEntry, DateUtils2.parseUTCToDate("2019-05-01T12:00:00.00Z"));
    }

    @Test
    public void testIsValidTimestamp() {
        LocalDateTime timestamp = LocalDateTime.now();
        io.mosip.kernel.keymanagerservice.entity.KeyAlias keyAlias = new io.mosip.kernel.keymanagerservice.entity.KeyAlias();
        keyAlias.setKeyGenerationTime(timestamp.minusDays(1));
        keyAlias.setKeyExpiryTime(timestamp.plusDays(30));

        boolean result = keymanagerUtil.isValidTimestamp(timestamp, keyAlias, 5);
        assertThat(result, isA(Boolean.class));
    }

    @Test
    public void testIsOverlapping() {
        LocalDateTime timestamp = LocalDateTime.now();
        LocalDateTime policyExpiryTime = timestamp.plusDays(30);
        LocalDateTime keyGenerationTime = timestamp.minusDays(5);
        LocalDateTime keyExpiryTime = timestamp.plusDays(25);

        boolean result = keymanagerUtil.isOverlapping(timestamp, policyExpiryTime, keyGenerationTime, keyExpiryTime);
        assertThat(result, isA(Boolean.class));
    }

    @Test
    public void testIsValidReferenceId() {
        boolean validResult = keymanagerUtil.isValidReferenceId("VALID_REF_ID");
        boolean invalidResult = keymanagerUtil.isValidReferenceId("");
        boolean nullResult = keymanagerUtil.isValidReferenceId(null);

        assertThat(validResult, isA(Boolean.class));
        assertThat(invalidResult, isA(Boolean.class));
        assertThat(nullResult, isA(Boolean.class));
    }

    @Test
    public void testParseToLocalDateTime() {
        String dateTimeStr = "2024-01-15T10:30:45.123Z";
        LocalDateTime result = keymanagerUtil.parseToLocalDateTime(dateTimeStr);
        assertThat(result, isA(LocalDateTime.class));
    }

    @Test
    public void testIsValidResponseType() {
        boolean validResult = keymanagerUtil.isValidResponseType("CSR");
        boolean invalidResult = keymanagerUtil.isValidResponseType("");
        boolean nullResult = keymanagerUtil.isValidResponseType(null);

        assertThat(validResult, isA(Boolean.class));
        assertThat(invalidResult, isA(Boolean.class));
        assertThat(nullResult, isA(Boolean.class));
    }

    @Test
    public void testIsValidApplicationId() {
        boolean validResult = keymanagerUtil.isValidApplicationId("REGISTRATION");
        boolean invalidResult = keymanagerUtil.isValidApplicationId("");
        boolean nullResult = keymanagerUtil.isValidApplicationId(null);

        assertThat(validResult, isA(Boolean.class));
        assertThat(invalidResult, isA(Boolean.class));
        assertThat(nullResult, isA(Boolean.class));
    }

    @Test
    public void testIsValidCertificateData() {
        String validCert = "-----BEGIN CERTIFICATE-----\nMIICertData\n-----END CERTIFICATE-----";
        boolean validResult = keymanagerUtil.isValidCertificateData(validCert);
        boolean invalidResult = keymanagerUtil.isValidCertificateData("");
        boolean nullResult = keymanagerUtil.isValidCertificateData(null);

        assertThat(validResult, isA(Boolean.class));
        assertThat(invalidResult, isA(Boolean.class));
        assertThat(nullResult, isA(Boolean.class));
    }

    @Test
    public void testGetPEMFormatedData() {
        String result = keymanagerUtil.getPEMFormatedData(keyPair.getPublic());
        assertThat(result, isA(String.class));
    }

    @Test
    public void testConvertToUTC() {
        java.util.Date testDate = new java.util.Date();
        LocalDateTime result = keymanagerUtil.convertToUTC(testDate);
        assertThat(result, isA(LocalDateTime.class));
    }

    @Test
    public void testGetUniqueIdentifier() {
        String input = "TEST_INPUT_STRING";
        String result = keymanagerUtil.getUniqueIdentifier(input);
        assertThat(result, isA(String.class));
    }

    @Test
    public void testConvertSanValuesToMap() {
        String sanValues = "{'DNS':'example.com','IP':'192.168.1.1'}";
        java.util.Map<String, String> result = keymanagerUtil.convertSanValuesToMap(sanValues);
        assertThat(result, isA(java.util.Map.class));

        // Test with null input
        java.util.Map<String, String> nullResult = keymanagerUtil.convertSanValuesToMap(null);
        assertThat(nullResult, isA(java.util.Map.class));
    }

    @Test
    public void testSetMetaData() {
        io.mosip.kernel.keymanagerservice.entity.KeyAlias entity = new io.mosip.kernel.keymanagerservice.entity.KeyAlias();
        io.mosip.kernel.keymanagerservice.entity.KeyAlias result = keymanagerUtil.setMetaData(entity);
        assertThat(result, isA(io.mosip.kernel.keymanagerservice.entity.KeyAlias.class));
    }

    @Test
    public void testConvertToCertificateFromString() {
        String certData = keymanagerUtil.getPEMFormatedData(chain[0]);
        java.security.cert.Certificate result = keymanagerUtil.convertToCertificate(certData);
        assertThat(result, isA(java.security.cert.Certificate.class));
    }

    @Test
    public void testConvertToCertificateFromBytes() throws Exception {
        byte[] certBytes = chain[0].getEncoded();
        java.security.cert.Certificate result = keymanagerUtil.convertToCertificate(certBytes);
        assertThat(result, isA(java.security.cert.Certificate.class));
    }

    @Test
    public void testGetCertificateParameters() {
        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusYears(1);
        io.mosip.kernel.core.keymanager.model.CertificateParameters result =
                keymanagerUtil.getCertificateParameters(chain[0].getSubjectX500Principal(), notBefore, notAfter);
        assertThat(result, isA(io.mosip.kernel.core.keymanager.model.CertificateParameters.class));
    }

    @Test
    public void testGetCertificateParametersWithRequest() {
        io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto request =
                new io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto();
        request.setReferenceId("TEST");
        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusYears(1);
        io.mosip.kernel.core.keymanager.model.CertificateParameters result =
                keymanagerUtil.getCertificateParameters(request, notBefore, notAfter, "REGISTRATION");
        assertThat(result, isA(io.mosip.kernel.core.keymanager.model.CertificateParameters.class));
    }

    @Test
    public void testGetCertificateParametersWithCSR() {
        io.mosip.kernel.keymanagerservice.dto.CSRGenerateRequestDto request =
                new io.mosip.kernel.keymanagerservice.dto.CSRGenerateRequestDto();
        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusYears(1);
        io.mosip.kernel.core.keymanager.model.CertificateParameters result =
                keymanagerUtil.getCertificateParameters(request, notBefore, notAfter);
        assertThat(result, isA(io.mosip.kernel.core.keymanager.model.CertificateParameters.class));
    }

    @Test
    public void testGetCertificateParametersWithCommonName() {
        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusYears(1);
        io.mosip.kernel.core.keymanager.model.CertificateParameters result =
                keymanagerUtil.getCertificateParameters("TestCN", notBefore, notAfter);
        assertThat(result, isA(io.mosip.kernel.core.keymanager.model.CertificateParameters.class));
    }

    @Test
    public void testGetCSR() {
        io.mosip.kernel.core.keymanager.model.CertificateParameters certParams =
                new io.mosip.kernel.core.keymanager.model.CertificateParameters();
        certParams.setCommonName("Test");
        certParams.setOrganizationUnit("OU");
        certParams.setOrganization("O");
        certParams.setLocation("L");
        certParams.setState("ST");
        certParams.setCountry("IN");
        String result = keymanagerUtil.getCSR(keyPair.getPrivate(), keyPair.getPublic(), certParams, "RSA");
        assertThat(result, isA(String.class));
    }

    @Test
    public void testDestoryPrivateKey() {
        keymanagerUtil.destoryKey(keyPair.getPrivate());
    }

    @Test(expected = io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException.class)
    public void testCheckAppIdAllowedForEd25519KeyGen() {
        keymanagerUtil.checkAppIdAllowedForEd25519KeyGen("INVALID_APP_ID");
    }

    @Test
    public void testGetSanValues() {
        java.util.Map<String, String> result = keymanagerUtil.getSanValues("REGISTRATION", "");
        assertThat(result, isA(java.util.Map.class));
    }

    @Test
    public void testPurgeKeyAliasTrustAnchorsCache() {
        keymanagerUtil.purgeKeyAliasTrustAnchorsCache();
    }

    @Test(expected = KeymanagerServiceException.class)
    public void testConvertToCertificateKeymanagerServiceException() {
        keymanagerUtil.convertToCertificate("INVALID_CERT_DATA");
        keymanagerUtil.convertToCertificate((byte[]) null);
    }

    @Test(expected = KeymanagerServiceException.class)
    public void testGetPEMFormatedDataKeymanagerServiceException() {
        keymanagerUtil.getPEMFormatedData("CERTIFICATE_DATA_INVALID");
    }

    @Test
    public void testDestroySecreteKey() throws NoSuchAlgorithmException {
        javax.crypto.KeyGenerator keyGenerator = javax.crypto.KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        javax.crypto.SecretKey secretKey = keyGenerator.generateKey();
        keymanagerUtil.destoryKey(secretKey);
    }

    @Test(expected = KeymanagerServiceException.class)
    public void testConvertToCertificateException() {
        String corruptPem = "-----BEGIN CERTIFICATE-----\n"
                + "VGhpcyBpcyBub3QgYSB2YWxpZCBjZXJ0IGRhdGE=\n"
                + "-----END CERTIFICATE-----";

        keymanagerUtil.convertToCertificate(corruptPem);

        keymanagerUtil.convertToCertificate((byte[]) corruptPem.getBytes());
    }

    @Test(expected = KeymanagerServiceException.class)
    public void testGetCSRException() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyPairGenerator keyPairGenerator2 = KeyPairGenerator.getInstance("EC");
        keyPairGenerator2.initialize(256);
        KeyPair keyPair2 = keyPairGenerator2.generateKeyPair();

        io.mosip.kernel.core.keymanager.model.CertificateParameters certParams = new io.mosip.kernel.core.keymanager.model.CertificateParameters();
        certParams.setCommonName("Test");
        certParams.setOrganizationUnit("OU");
        certParams.setOrganization("O");
        certParams.setLocation("Bengaluru");
        certParams.setState("ST");
        certParams.setCountry("IN");
        keymanagerUtil.getCSR(keyPair2.getPrivate(), keyPair.getPublic(), certParams, "RSA");
    }

    @Test
    public void testPrivateKeyExtractor() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        byte[] keyBytes = keyPair.getPrivate().getEncoded();
        String b64String = CryptoUtil.encodeToURLSafeBase64(keyBytes);
        keymanagerUtil.destoryKey(keyPair.getPrivate());

        InputStream inputStream = new ByteArrayInputStream(b64String.getBytes("UTF-8"));
        PrivateKey privateKey = keymanagerUtil.privateKeyExtractor(inputStream);
        assertThat(privateKey, isA(PrivateKey.class));
        assertEquals(privateKey.getAlgorithm(), "RSA");

        b64String = "Invalid Base64 Key Bytes";
        InputStream invalidInputStream = new ByteArrayInputStream(b64String.getBytes());
        KeystoreProcessingException exception = assertThrows(KeystoreProcessingException.class, () -> {
            keymanagerUtil.privateKeyExtractor(invalidInputStream);
        });
        assertThat(exception, isA(KeystoreProcessingException.class));
        assertEquals(KeymanagerErrorCode.KEYSTORE_PROCESSING_ERROR.getErrorCode(), exception.getErrorCode());
    }
}