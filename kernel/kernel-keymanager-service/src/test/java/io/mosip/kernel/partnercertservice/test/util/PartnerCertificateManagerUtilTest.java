package io.mosip.kernel.partnercertservice.test.util;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Optional;

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
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
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

    @Before
    public void setUp() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        // Get test certificates
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        selfSignedCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(rootCert.getCertificate());
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
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        boolean result = PartnerCertificateManagerUtil.isSelfSignedCertificate(testCertificate);
        Assert.assertFalse(result);
    }

    @Test
    public void testIsMinValidityCertificate_Valid() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        boolean result = PartnerCertificateManagerUtil.isMinValidityCertificate(testCertificate, 1);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsMinValidityCertificate_Invalid() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        boolean result = PartnerCertificateManagerUtil.isMinValidityCertificate(testCertificate, 1200);
        Assert.assertFalse(result);
    }

    @Test
    public void testIsFutureDatedCertificate_Valid() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        boolean result = PartnerCertificateManagerUtil.isFutureDatedCertificate(testCertificate);
        Assert.assertTrue(result);
    }

    @Test
    public void testFormatCertificateDN_Success() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

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
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        String thumbprint = PartnerCertificateManagerUtil.getCertificateThumbprint(testCertificate);
        
        Assert.assertNotNull(thumbprint);
        Assert.assertFalse(thumbprint.isEmpty());
        Assert.assertEquals(40, thumbprint.length());
    }

    @Test
    public void testIsCertificateDatesValid_Valid() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        boolean result = PartnerCertificateManagerUtil.isCertificateDatesValid(testCertificate);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsCertificateValidForDuration_Valid() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        boolean result = PartnerCertificateManagerUtil.isCertificateValidForDuration(testCertificate, 1, 30);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsCertificateValidForDuration_Invalid() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        boolean result = PartnerCertificateManagerUtil.isCertificateValidForDuration(testCertificate, 100, 0);
        Assert.assertFalse(result);
    }

    @Test
    public void testIsCertificateValidForDuration_NegativeDays() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

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
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());
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
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());
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
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        Certificate[] certChain = {testCertificate, selfSignedCertificate};
        
        String p7bChain = PartnerCertificateManagerUtil.buildP7BCertificateChain(
            Arrays.asList(certChain), testCertificate, "FTM", false, 
            selfSignedCertificate, testCertificate);
        
        Assert.assertNotNull(p7bChain);
        Assert.assertFalse(p7bChain.isEmpty());
    }

    @Test
    public void testBuildP7BCertificateChain_NonFTMDomain() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        Certificate[] certChain = {testCertificate, selfSignedCertificate};
        
        String p7bChain = PartnerCertificateManagerUtil.buildP7BCertificateChain(
            Arrays.asList(certChain), testCertificate, "DEVICE", true, 
            selfSignedCertificate, testCertificate);
        
        Assert.assertNotNull(p7bChain);
        Assert.assertFalse(p7bChain.isEmpty());
    }

    @Test
    public void testBuildp7bFile_Success() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());

        Certificate[] certChain = {testCertificate, selfSignedCertificate};
        
        String p7bFile = PartnerCertificateManagerUtil.buildp7bFile(certChain);
        
        Assert.assertNotNull(p7bFile);
        Assert.assertTrue(p7bFile.contains("-----BEGIN PKCS7-----"));
        Assert.assertTrue(p7bFile.contains("-----END PKCS7-----"));
    }

    @Test
    public void testBuildCertChainWithPKCS7_Success() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        X509Certificate testCertificate = (X509Certificate) keymanagerUtil.convertToCertificate(pmsCert.getCertificate());
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