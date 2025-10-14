package io.mosip.kernel.partnercertservice.test.util;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.entity.CACertificateStore;
import io.mosip.kernel.keymanagerservice.repository.CACertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.partnercertservice.util.PartnerCertificateManagerUtil;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class PartnerCertificateManagerUtilTest {

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeymanagerUtil keymanagerUtil;

    @Autowired
    private CACertificateStoreRepository caCertificateStoreRepository;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    private X509Certificate selfSignedCertificate;

    private String interCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDbTCCAlWgAwIBAgIUVB019PvL2p+YbdMZydcBmd3SydcwDQYJKoZIhvcNAQEL\n" +
            "BQAwbzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
            "cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRowGAYDVQQD\n" +
            "DBFQTVMtcm9vdC10ZXN0Y2FzZTAgFw0yNTEwMTMxMzQ2NDNaGA8yMTI0MTAxMzEz\n" +
            "NDY0M1owcDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5n\n" +
            "YWx1cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRswGQYD\n" +
            "VQQDDBJQTVMtaW50ZXItdGVzdGNhc2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
            "ggEKAoIBAQCVULKkf6haXwl7AQJG1iDWcPy5dNa8wqALEOnwAEGrRcWHgGy+UPEf\n" +
            "8KiwOyOTDMY5ioq4LK5DWCc4RJ0m8JzmhppHq4xQhXkucjLMPgM3+MBljvOQDSlh\n" +
            "u9hgelTF44LP9RPTWePXroTwGHe6Kc9/S93KNh6+MU29TbuW7nY/xEBpf0D58iwF\n" +
            "y3axO3SjEnnRkWaL+v4agYCV8xs92UaLoEw3gGzRb9tDUWEkxyJUyGxzelIV3XgW\n" +
            "+a29QWp2qJRupe4c5yfG+d/cbdDyBvVSxQKQBMGAiCb8Xi3SmDUYgkDgJsRgKUc7\n" +
            "w3xfB3+cyyG75PaA80p8hjsxzY5ZUJh1AgMBAAEwDQYJKoZIhvcNAQELBQADggEB\n" +
            "AJKwswIouSJB3LShLLqPx5b602FlzHmYTG8xIr7aWYjknHDoj6KEod4+wro999Hx\n" +
            "KEERIu79rw0HZtj0uVe+nZK3OJaKcKRhTlzrErrg/niZlvp4E2imMGNug+3npphY\n" +
            "4zhW3sWR2QPv3tNmm+C35jCKY30o5wYwSlOqTdHG/iq6XabYOaLHYjz9fe0ynWFL\n" +
            "0HS8B9fpW7jiz2u/XelIQnjPz8GrS66mjYJzdyx9YKiVi72fFUdtceubihyJSucJ\n" +
            "3XJvNPXeyNuCVCiwv8frI1mkkWyi//I+qxjmbQEkbAP1eLwiirier56MidZa6ZDt\n" +
            "TqOhYcxaaqJaO+XnmrzedjM=\n" +
            "-----END CERTIFICATE-----\n";

    @Before
    public void setUp() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        // Get test certificates
        String caCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDbDCCAlSgAwIBAgIUTW8ScXGEgz/C0o7xnAsBmd3P8hswDQYJKoZIhvcNAQEL\n" +
                "BQAwbzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
                "cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRowGAYDVQQD\n" +
                "DBFQTVMtcm9vdC10ZXN0Y2FzZTAgFw0yNTEwMTMxMzQzMzZaGA8yMTI1MTAxMzEz\n" +
                "NDMzNlowbzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5n\n" +
                "YWx1cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRowGAYD\n" +
                "VQQDDBFQTVMtcm9vdC10ZXN0Y2FzZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
                "AQoCggEBANZqa/+RIVKaoIiQ11pFXOCL1NgOd6F1a98KIWU3ZZ8Kh/CjPN5V5QN/\n" +
                "pqLX5/4+Zw4tJJqsruQmCz76LCLFREuoWTByNtnKZDni1quNRkcz7uiKeOLFHzk4\n" +
                "QODDF4BfefaQElOLSMdHueoKgWBor+/E9aK8+vvk3kPOtC67RmhWCJ5TAI19kCaY\n" +
                "lBrneAx+JmQxJ8sAHszErHxjdlEIUNSoU4GbIrgw4C8dtdG6yVb3arM9+kCsa0hg\n" +
                "JGYCW8igi8P0yyUoeGpi86ZiYjiIVGZS7dmZM/vGun+JjaHtTlBCvCsMxVstrhMZ\n" +
                "AgVZouiaXgmbvubSXDuBBOL6pDRWFocCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
                "irKsATgEedB8IoD4WeGW7KRuPxT6iow4yQUf9kODEYzsNKRdvowUD97MnORaF1ns\n" +
                "EtA+vTfutktHHMhnBNfuFyZFsZCqq3skbRGst9RjxokznljE/OZc0q+24Hm9dRfZ\n" +
                "SMBYWPEnFQzpvPmOexLwRRwt6EGrZPWUh22NGYLbJR22CP5wTgsUKwA6MHcAVVTS\n" +
                "5+WcxMD0OMoRX5LIlFLUSyyZb6POs/lsta7+fr2FU84FNLrooz0Q+8/QzTpW/XND\n" +
                "N3yr7o9LBHFXwVB+Fb6ow4/r9hPuBFg58FM+wQt5AJ5cz/LeOKsVpDJ8Bvuodrxa\n" +
                "vb31TtM0csPVLODrpnNZyA==\n" +
                "-----END CERTIFICATE-----";

        selfSignedCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(caCert);
    }

    @After
    public void tearDown() {
        caCertificateStoreRepository.deleteAll();
        keyStoreRepository.deleteAll();
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testIsSelfSignedCertificate_SelfSigned() {
        boolean result = PartnerCertificateManagerUtil.isSelfSignedCertificate(selfSignedCertificate);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsSelfSignedCertificate_NotSelfSigned() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        boolean result = PartnerCertificateManagerUtil.isSelfSignedCertificate(testCertificate);
        Assert.assertFalse(result);
    }

    @Test
    public void testIsMinValidityCertificate_Valid() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        boolean result = PartnerCertificateManagerUtil.isMinValidityCertificate(testCertificate, 1);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsMinValidityCertificate_Invalid() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        boolean result = PartnerCertificateManagerUtil.isMinValidityCertificate(testCertificate, 1200);
        Assert.assertFalse(result);
    }

    @Test
    public void testIsFutureDatedCertificate_Valid() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        boolean result = PartnerCertificateManagerUtil.isFutureDatedCertificate(testCertificate);
        Assert.assertTrue(result);
    }

    @Test
    public void testFormatCertificateDN_Success() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        String dn = testCertificate.getSubjectX500Principal().getName();
        String formattedDN = PartnerCertificateManagerUtil.formatCertificateDN(dn);
        
        Assert.assertNotNull(formattedDN);
        Assert.assertFalse(formattedDN.isEmpty());
    }

    @Test
    public void testFormatCertificateDN_EmptyDN() {
        String formattedDN = PartnerCertificateManagerUtil.formatCertificateDN("CN=");
        Assert.assertNotNull(formattedDN);
    }

    @Test
    public void testGetCertificateThumbprint_Success() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        String thumbprint = PartnerCertificateManagerUtil.getCertificateThumbprint(testCertificate);
        
        Assert.assertNotNull(thumbprint);
        Assert.assertFalse(thumbprint.isEmpty());
        Assert.assertEquals(40, thumbprint.length());
    }

    @Test
    public void testIsCertificateDatesValid_Valid() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        boolean result = PartnerCertificateManagerUtil.isCertificateDatesValid(testCertificate);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsCertificateValidForDuration_Valid() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        boolean result = PartnerCertificateManagerUtil.isCertificateValidForDuration(testCertificate, 1, 30);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsCertificateValidForDuration_Invalid() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        boolean result = PartnerCertificateManagerUtil.isCertificateValidForDuration(testCertificate, 100, 0);
        Assert.assertFalse(result);
    }

    @Test
    public void testIsCertificateValidForDuration_NegativeDays() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        boolean result = PartnerCertificateManagerUtil.isCertificateValidForDuration(testCertificate, 1, 400);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsValidTimestamp_Valid() {
        CACertificateStore certStore = new CACertificateStore();
        certStore.setCertNotBefore(DateUtils.getUTCCurrentDateTime().minusDays(1));
        certStore.setCertNotAfter(DateUtils.getUTCCurrentDateTime().plusDays(1));
        
        LocalDateTime currentTime = DateUtils.getUTCCurrentDateTime();
        boolean result = PartnerCertificateManagerUtil.isValidTimestamp(currentTime, certStore);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsValidTimestamp_Invalid() {
        CACertificateStore certStore = new CACertificateStore();
        certStore.setCertNotBefore(DateUtils.getUTCCurrentDateTime().plusDays(1));
        certStore.setCertNotAfter(DateUtils.getUTCCurrentDateTime().plusDays(2));
        
        LocalDateTime currentTime = DateUtils.getUTCCurrentDateTime();
        boolean result = PartnerCertificateManagerUtil.isValidTimestamp(currentTime, certStore);
        Assert.assertFalse(result);
    }

    @Test
    public void testIsValidTimestamp_ExactMatch() {
        LocalDateTime exactTime = DateUtils.getUTCCurrentDateTime();
        CACertificateStore certStore = new CACertificateStore();
        certStore.setCertNotBefore(exactTime);
        certStore.setCertNotAfter(exactTime.plusDays(1));
        
        boolean result = PartnerCertificateManagerUtil.isValidTimestamp(exactTime, certStore);
        Assert.assertTrue(result);
    }

    @Test
    public void testGetCertificateOrgName_Success() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);
        X500Principal principal = testCertificate.getSubjectX500Principal();
        String orgName = PartnerCertificateManagerUtil.getCertificateOrgName(principal);
        Assert.assertNotNull(orgName);
    }

    @Test
    public void testGetCertificateOrgName_NoOrg() {
        X500Principal principal = new X500Principal("CN=Test");
        String orgName = PartnerCertificateManagerUtil.getCertificateOrgName(principal);
        
        Assert.assertEquals("", orgName);
    }

    @Test
    public void testIsValidCertificateID_Valid() {
        boolean result = PartnerCertificateManagerUtil.isValidCertificateID("valid-cert-id");
        Assert.assertTrue(result);
    }

    @Test
    public void testIsValidCertificateID_Null() {
        boolean result = PartnerCertificateManagerUtil.isValidCertificateID(null);
        Assert.assertFalse(result);
    }

    @Test
    public void testIsValidCertificateID_Empty() {
        boolean result = PartnerCertificateManagerUtil.isValidCertificateID("");
        Assert.assertFalse(result);
    }

    @Test
    public void testIsValidCertificateID_Whitespace() {
        boolean result = PartnerCertificateManagerUtil.isValidCertificateID("   ");
        Assert.assertFalse(result);
    }

    @Test
    public void testGetCertificateParameters_Success() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);
        X500Principal principal = testCertificate.getSubjectX500Principal();
        LocalDateTime notBefore = DateUtils.getUTCCurrentDateTime();
        LocalDateTime notAfter = notBefore.plusDays(365);
        
        CertificateParameters params = PartnerCertificateManagerUtil.getCertificateParameters(
            principal, notBefore, notAfter);
        
        Assert.assertNotNull(params);
        Assert.assertNotNull(params.getCommonName());
        Assert.assertEquals(notBefore, params.getNotBefore());
        Assert.assertEquals(notAfter, params.getNotAfter());
    }

    @Test
    public void testBuildP7BCertificateChain_FTMDomain() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        Certificate[] certChain = {testCertificate, selfSignedCertificate};
        
        String p7bChain = PartnerCertificateManagerUtil.buildP7BCertificateChain(
            Arrays.asList(certChain), testCertificate, "FTM", false, 
            selfSignedCertificate, testCertificate);
        
        Assert.assertNotNull(p7bChain);
        Assert.assertFalse(p7bChain.isEmpty());
    }

    @Test
    public void testBuildP7BCertificateChain_NonFTMDomain() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        Certificate[] certChain = {testCertificate, selfSignedCertificate};
        
        String p7bChain = PartnerCertificateManagerUtil.buildP7BCertificateChain(
            Arrays.asList(certChain), testCertificate, "DEVICE", true, 
            selfSignedCertificate, testCertificate);
        
        Assert.assertNotNull(p7bChain);
        Assert.assertFalse(p7bChain.isEmpty());
    }

    @Test
    public void testBuildp7bFile_Success() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);

        Certificate[] certChain = {testCertificate, selfSignedCertificate};
        
        String p7bFile = PartnerCertificateManagerUtil.buildp7bFile(certChain);
        
        Assert.assertNotNull(p7bFile);
        Assert.assertTrue(p7bFile.contains("-----BEGIN PKCS7-----"));
        Assert.assertTrue(p7bFile.contains("-----END PKCS7-----"));
    }

    @Test
    public void testBuildCertChainWithPKCS7_Success() {
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(interCertificate);
        Certificate[] certChain = {testCertificate, selfSignedCertificate};
        
        String pkcs7Chain = PartnerCertificateManagerUtil.buildCertChainWithPKCS7(certChain);
        
        Assert.assertNotNull(pkcs7Chain);
        Assert.assertTrue(pkcs7Chain.contains("-----BEGIN PKCS7-----"));
        Assert.assertTrue(pkcs7Chain.contains("-----END PKCS7-----"));
    }

    @Test
    public void testHandleNullOrEmpty_Null() {
        String result = PartnerCertificateManagerUtil.handleNullOrEmpty(null);
        Assert.assertNull(result);
    }

    @Test
    public void testHandleNullOrEmpty_Empty() {
        String result = PartnerCertificateManagerUtil.handleNullOrEmpty("");
        Assert.assertNull(result);
    }

    @Test
    public void testHandleNullOrEmpty_Whitespace() {
        String result = PartnerCertificateManagerUtil.handleNullOrEmpty("   ");
        Assert.assertNull(result);
    }

    @Test
    public void testHandleNullOrEmpty_Valid() {
        String input = "valid-value";
        String result = PartnerCertificateManagerUtil.handleNullOrEmpty(input);
        Assert.assertEquals(input, result);
    }

    @Test
    public void testFormatCertificateDN_ComplexDN() {
        String complexDN = "CN=Test User,OU=IT Department,O=MOSIP,L=Bangalore,ST=Karnataka,C=IN";
        String formattedDN = PartnerCertificateManagerUtil.formatCertificateDN(complexDN);
        
        Assert.assertNotNull(formattedDN);
        Assert.assertTrue(formattedDN.contains("CN=Test User"));
        Assert.assertTrue(formattedDN.contains("O=MOSIP"));
        Assert.assertTrue(formattedDN.contains("C=IN"));
    }

    @Test
    public void testFormatCertificateDN_PartialDN() {
        String partialDN = "CN=Test User,O=MOSIP";
        String formattedDN = PartnerCertificateManagerUtil.formatCertificateDN(partialDN);
        
        Assert.assertNotNull(formattedDN);
        Assert.assertTrue(formattedDN.contains("CN=Test User"));
        Assert.assertTrue(formattedDN.contains("O=MOSIP"));
    }

    @Test
    public void testGetCertificateParameters_MinimalPrincipal() {
        X500Principal minimalPrincipal = new X500Principal("CN=Minimal Test");
        LocalDateTime notBefore = DateUtils.getUTCCurrentDateTime();
        LocalDateTime notAfter = notBefore.plusDays(30);
        
        CertificateParameters params = PartnerCertificateManagerUtil.getCertificateParameters(
            minimalPrincipal, notBefore, notAfter);
        
        Assert.assertNotNull(params);
        Assert.assertEquals("Minimal Test", params.getCommonName());
        Assert.assertEquals("", params.getOrganization());
        Assert.assertEquals("", params.getCountry());
    }
}