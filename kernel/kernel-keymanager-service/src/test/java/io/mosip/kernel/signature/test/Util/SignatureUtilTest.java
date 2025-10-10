package io.mosip.kernel.signature.test.Util;

import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.signature.dto.CWTSignRequestDto;
import io.mosip.kernel.signature.exception.RequestException;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.util.SignatureUtil;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.cert.X509Certificate;
import java.util.*;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class SignatureUtilTest {

    @Autowired
    private SignatureUtil signatureUtil;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeymanagerUtil keymanagerUtil;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    private String testUniqueId = "1234567890ABCDEF";

    @Before
    public void setUp() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
    }

    @After
    public void tearDown() {
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testIsDataValid() {
        Assert.assertTrue(SignatureUtil.isDataValid("valid data"));
        Assert.assertFalse(SignatureUtil.isDataValid(null));
        Assert.assertFalse(SignatureUtil.isDataValid(""));
        Assert.assertFalse(SignatureUtil.isDataValid("   "));
    }

    @Test
    public void testIsJsonValid() {
        Assert.assertTrue(SignatureUtil.isJsonValid("{\"key\":\"value\"}"));
        Assert.assertTrue(SignatureUtil.isJsonValid("[1,2,3]"));
        Assert.assertFalse(SignatureUtil.isJsonValid("invalid json"));
        Assert.assertFalse(SignatureUtil.isJsonValid("{invalid}"));
    }

    @Test
    public void testIsIncludeAttrsValid() {
        Assert.assertTrue(SignatureUtil.isIncludeAttrsValid(true));
        Assert.assertFalse(SignatureUtil.isIncludeAttrsValid(false));
    }

    @Test
    public void testIsCertificateDatesValid() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto certDeatils = keymanagerService.getCertificate("TEST", Optional.empty());
        X509Certificate x509Certificate = (X509Certificate) keymanagerUtil.convertToCertificate(certDeatils.getCertificate());
        Assert.assertTrue(SignatureUtil.isCertificateDatesValid(x509Certificate));
    }

    @Test
    public void testGetJWSHeader() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto certDeatils = keymanagerService.getCertificate("TEST", Optional.empty());
        X509Certificate x509Certificate = (X509Certificate) keymanagerUtil.convertToCertificate(certDeatils.getCertificate());

        var header = SignatureUtil.getJWSHeader("PS256", true, true, true, 
            "https://test.com/cert", x509Certificate, testUniqueId, true, "test:");
        Assert.assertNotNull(header);
        Assert.assertEquals("PS256", header.getAlgorithm().getName());
        Assert.assertNotNull(header.getX509CertChain());
        Assert.assertNotNull(header.getX509CertSHA256Thumbprint());
        Assert.assertNotNull(header.getKeyID());
    }

    @Test
    public void testGetJWSHeaderWithDifferentAlgorithms() {
        var rsHeader = SignatureUtil.getJWSHeader("RS256", false, false, false, null, null, testUniqueId, false, "");
        Assert.assertEquals("RS256", rsHeader.getAlgorithm().getName());
        
        var esHeader = SignatureUtil.getJWSHeader("ES256", false, false, false, null, null, testUniqueId, false, "");
        Assert.assertEquals("ES256", esHeader.getAlgorithm().getName());
        
        var eskHeader = SignatureUtil.getJWSHeader("ES256K", false, false, false, null, null, testUniqueId, false, "");
        Assert.assertEquals("ES256K", eskHeader.getAlgorithm().getName());
        
        var edHeader = SignatureUtil.getJWSHeader("EdDSA", false, false, false, null, null, testUniqueId, false, "");
        Assert.assertEquals("EdDSA", edHeader.getAlgorithm().getName());
    }

    @Test
    public void testBuildSignData() {
        var header = SignatureUtil.getJWSHeader("PS256", true, false, false, null, null, testUniqueId, false, "");
        byte[] payload = "test payload".getBytes();
        byte[] signData = SignatureUtil.buildSignData(header, payload);
        Assert.assertNotNull(signData);
        Assert.assertTrue(signData.length > payload.length);
    }

    @Test
    public void testConvertHexToBase64() {
        String result = SignatureUtil.convertHexToBase64("1234567890ABCDEF");
        Assert.assertNotNull(result);
        
        String nullResult = SignatureUtil.convertHexToBase64("invalid hex");
        Assert.assertNull(nullResult);
    }

    @Test
    public void testGetSignAlgorithm() {
        Assert.assertEquals("PS256", SignatureUtil.getSignAlgorithm(null));
        Assert.assertEquals("PS256", SignatureUtil.getSignAlgorithm(""));
        Assert.assertEquals("ES256", SignatureUtil.getSignAlgorithm("EC_SECP256R1_SIGN"));
        Assert.assertEquals("ES256K", SignatureUtil.getSignAlgorithm("EC_SECP256K1_SIGN"));
        Assert.assertEquals("EdDSA", SignatureUtil.getSignAlgorithm("ED25519_SIGN"));
        Assert.assertEquals("PS256", SignatureUtil.getSignAlgorithm("OTHER"));
    }

    @Test
    public void testGetIssuerFromPayload() {
        String payload = "{\"iss\":\"test-issuer\",\"data\":\"value\"}";
        String issuer = SignatureUtil.getIssuerFromPayload(payload);
        Assert.assertEquals("test-issuer", issuer);
        
        String noIssuer = SignatureUtil.getIssuerFromPayload("{\"data\":\"value\"}");
        Assert.assertEquals("", noIssuer);
        
        String invalidJson = SignatureUtil.getIssuerFromPayload("invalid json");
        Assert.assertEquals("", invalidJson);
    }

    @Test
    public void testGetJWSHeaderV2WithNullHeaders() {
        var header = signatureUtil.getJWSHeaderV2("PS256", false, false, false, 
            null, null, testUniqueId, false, "", null);
        Assert.assertNotNull(header);
    }

    @Test
    public void testBuildCWTClaimSet() {
        CWTSignRequestDto requestDto = new CWTSignRequestDto();
        requestDto.setIssuer("test-issuer");
        requestDto.setSubject("test-subject");
        requestDto.setAudience("test-audience");
        requestDto.setExpireDays(30);
        requestDto.setNotBeforeDays(0);
        requestDto.setPayload(CryptoUtil.encodeToURLSafeBase64("{\"custom\":\"data\",\"1\":\"value\"}".getBytes()));
        requestDto.setClaim169Payload("1234567890ABCDEF");
        
        byte[] claimSet = signatureUtil.buildCWTClaimSet(requestDto);
        Assert.assertNotNull(claimSet);
        Assert.assertTrue(claimSet.length > 0);
    }

    @Test
    public void testBuildCWTClaimSetWithDefaults() {
        CWTSignRequestDto requestDto = new CWTSignRequestDto();
        requestDto.setPayload(CryptoUtil.encodeToURLSafeBase64("{\"test\":\"data\"}".getBytes()));
        
        byte[] claimSet = signatureUtil.buildCWTClaimSet(requestDto);
        Assert.assertNotNull(claimSet);
    }

    @Test(expected = RequestException.class)
    public void testBuildCWTClaimSetInvalidJson() {
        CWTSignRequestDto requestDto = new CWTSignRequestDto();
        requestDto.setPayload(CryptoUtil.encodeToURLSafeBase64("invalid json".getBytes()));
        signatureUtil.buildCWTClaimSet(requestDto);
    }

    @Test(expected = KeymanagerServiceException.class)
    public void testBuildCWTClaimSetNegativeDays() {
        CWTSignRequestDto requestDto = new CWTSignRequestDto();
        requestDto.setExpireDays(-1);
        signatureUtil.buildCWTClaimSet(requestDto);
    }

    @Test
    public void testIsNotBeforeDateValid() {
        Date pastDate = DateUtils.addDays(new Date(), -1);
        Assert.assertTrue(signatureUtil.isNotBeforeDateValid(pastDate));
        
        Date futureDate = DateUtils.addDays(new Date(), 1);
        Assert.assertFalse(signatureUtil.isNotBeforeDateValid(futureDate));
    }

    @Test
    public void testIsExpireDateValid() {
        Date futureDate = DateUtils.addDays(new Date(), 1);
        Assert.assertTrue(signatureUtil.isExpireDateValid(futureDate));
        
        Date pastDate = DateUtils.addDays(new Date(), -1);
        Assert.assertFalse(signatureUtil.isExpireDateValid(pastDate));
    }

    @Test
    public void testFilterMapEntries() {
        Map<String, Object> protectedMap = new HashMap<>();
        protectedMap.put("includeCertificateChain", true);
        protectedMap.put("other", true);
        
        Map<String, Object> unprotectedMap = new HashMap<>();
        unprotectedMap.put("includeCertificateChain", false);
        unprotectedMap.put("includeCertificate", false);
        unprotectedMap.put("keep", "value");
        
        Map<String, Object> result = SignatureUtil.filterMapEntries(protectedMap, unprotectedMap);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.containsKey("keep"));
        Assert.assertFalse(result.containsKey("includeCertificateChain"));
    }

    @Test
    public void testFilterMapEntriesWithIncludeCert() {
        Map<String, Object> protectedMap = new HashMap<>();
        protectedMap.put("includeCertificate", true);
        
        Map<String, Object> unprotectedMap = new HashMap<>();
        unprotectedMap.put("includeCertificate", false);
        unprotectedMap.put("keep", "value");
        
        Map<String, Object> result = SignatureUtil.filterMapEntries(protectedMap, unprotectedMap);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.containsKey("keep"));
    }

    @Test
    public void testFilterMapEntriesNullProtected() {
        Map<String, Object> unprotectedMap = new HashMap<>();
        unprotectedMap.put("key", "value");
        
        Map<String, Object> result = SignatureUtil.filterMapEntries(null, unprotectedMap);
        Assert.assertEquals(unprotectedMap, result);
    }

    @Test
    public void testIsNumeric() {
        Assert.assertTrue(SignatureUtil.isNumeric("123"));
        Assert.assertTrue(SignatureUtil.isNumeric("0"));
        Assert.assertTrue(SignatureUtil.isNumeric("-123"));
        Assert.assertFalse(SignatureUtil.isNumeric("abc"));
        Assert.assertFalse(SignatureUtil.isNumeric("12.3"));
        Assert.assertFalse(SignatureUtil.isNumeric(""));
    }

    @Test
    public void testDecodeHex() {
        byte[] result = signatureUtil.decodeHex("48656C6C6F"); // "Hello" in hex
        Assert.assertNotNull(result);
        Assert.assertEquals("Hello", new String(result));
        
        byte[] nullResult = signatureUtil.decodeHex(null);
        Assert.assertNull(nullResult);
        
        byte[] emptyResult = signatureUtil.decodeHex("");
        Assert.assertNull(emptyResult);
    }

    @Test(expected = SignatureFailureException.class)
    public void testDecodeHexInvalid() {
        signatureUtil.decodeHex("invalid hex");
    }
}
