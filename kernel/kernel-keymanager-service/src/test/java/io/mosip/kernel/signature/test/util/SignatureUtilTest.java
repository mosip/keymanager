package io.mosip.kernel.signature.test.util;

import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
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

    private String expiredCertificate = """
            -----BEGIN CERTIFICATE-----
            MIICtjCCAZ6gAwIBAgIUZm9Jj2wIadCiDIB2TW4Bmv4KpZgwDQYJKoZIhvcNAQEL
            BQAwFTETMBEGA1UEAwwKY2EtZXhwaXJlZDAeFw0yMjEyMDgxMjU4MjFaFw0yNDEy
            MDgxMjU4MjFaMBUxEzARBgNVBAMMCmNhLWV4cGlyZWQwggEiMA0GCSqGSIb3DQEB
            AQUAA4IBDwAwggEKAoIBAQCs9s18I+s77QlzfWN0+RRhyQ29orYBSbHBp8dRyz1x
            Tl9z699Bj/uzwIHPt18Qc0+9eFhtGzhPquCAsJTUeLkR1jGzvVVuAyhO1EeOvxeI
            BVT45vBG+Qtm7cqMSkyE//eint3BhKyp2ySK4MUGPLSUkmNQ6GGuIaRyV2efwsZe
            2EVJsK4JkT5gzhlwW++7R8Aei1+UDdCADqJorDsPQTam8VVFZKlqm6U4SyPnicgh
            /Q4ODHWeoM5LjoLYdGPp7EluGHY+4Zoyay7frMBM8zCWf+qJUwXS/EtBRNMI9Pzy
            CJHK5FWQ/BwDpFN2HbHolgH+busVr13vTiMx8O6zuMxVAgMBAAEwDQYJKoZIhvcN
            AQELBQADggEBAKQv7+m1lfNwkeocMKCvxB1dppM+80aEle12YuWi7WkfZ1TJGwXo
            RqbYdRa6szURARUNolFvRlbQxEJzkXtgElEw7/BFHWejFGMU6MT+191exQQWpXsf
            kAjUhSlPLKD45aN6OguL//XF673Ripi2d3Nz+0PjFGjvth+oH7HyE2/6/8GoNvfz
            +GI0+J35nBEt/2O36FIcxTjVq7GqJudVEE1w4j2o7iW9tBRlPeLZMvhsIjiCCiBK
            dIGptqfav9V3Hqai+p0m8BxEUMINCgciPRCzdSybSnFLrkZCSKmhK18B+z/1xt5b
            1QWPHILmhDQuLCfY/f6Ztvs+0PBC2ADGlRo=
            -----END CERTIFICATE-----
            """;

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
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto certDeatils = keymanagerService.getCertificate("TEST", Optional.empty());
        X509Certificate x509Certificate = (X509Certificate) keymanagerUtil.convertToCertificate(certDeatils.getCertificate());
        var header = signatureUtil.getJWSHeaderV2("PS256", false, false, false,
                "https://test.com/cert", x509Certificate, testUniqueId, false, "", null);
        Assert.assertNotNull(header);
    }

    @Test
    public void testIsCertificateDatesValidFalse() {
        X509Certificate expiredCert = (X509Certificate) keymanagerUtil.convertToCertificate(expiredCertificate);
        Assert.assertFalse(SignatureUtil.isCertificateDatesValid(expiredCert));
    }
}