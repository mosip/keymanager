package io.mosip.kernel.partnercertservice.test.service;

import static org.junit.jupiter.api.Assertions.*;

import java.security.cert.X509Certificate;
import java.util.*;

import io.mosip.kernel.keymanagerservice.entity.CACertificateStore;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.repository.CACertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository;
import io.mosip.kernel.keymanagerservice.repository.PartnerCertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.partnercertservice.dto.*;
import io.mosip.kernel.partnercertservice.exception.PartnerCertManagerException;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class PartnerCertificateManagerServiceTest {

    @Autowired
    private PartnerCertificateManagerService partnerCertService;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeymanagerUtil keymanagerUtil;

    @Autowired
    private CACertificateStoreRepository caCertificateStoreRepository;

    @Autowired
    private PartnerCertificateStoreRepository partnerCertificateStoreRepository;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    @Before
    public void setUp() {
        // Generate master keys for testing
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
    }

    @After
    public void tearDown() {
        partnerCertificateStoreRepository.deleteAll();
        caCertificateStoreRepository.deleteAll();
        keyStoreRepository.deleteAll();
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testUploadCACertificate_Success() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(validCACertData);
        requestDto.setPartnerDomain("FTM");

        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);

        Assert.assertNotNull(response);
        Assert.assertEquals("Upload Success.", response.getStatus());
        Assert.assertNotNull(response.getTimestamp());

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        requestDto.setCertificateData(validPartnerCertData);
        response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testUploadCACertificate_InvalidCertificate() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData("invalid-certificate-data");
        requestDto.setPartnerDomain("FTM");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-001", exception.getErrorCode());
    }

    @Test
    public void testUploadCACertificate_InvalidPartnerDomain() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(validCACertData);
        requestDto.setPartnerDomain("INVALID_DOMAIN");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-011", exception.getErrorCode());
    }

    @Test
    public void testUploadCACertificate_DuplicateCertificate() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(validCACertData);
        requestDto.setPartnerDomain("FTM");

        // Upload first time
        partnerCertService.uploadCACertificate(requestDto);

        // Try to upload same certificate again
        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-003", exception.getErrorCode());
    }

    @Test
    public void testUploadPartnerCertificate_Success() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        // First upload CA certificate
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        // Now upload partner certificate
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(validPartnerCertData);
        requestDto.setOrganizationName("IITB");
        requestDto.setPartnerDomain("FTM");

        PartnerCertificateResponseDto response = partnerCertService.uploadPartnerCertificate(requestDto);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getCertificateId());
        Assert.assertNotNull(response.getSignedCertificateData());
        Assert.assertNotNull(response.getTimestamp());
    }

    @Test
    public void testUploadPartnerCertificate_InvalidCertificate() {
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData("invalid-certificate-data");
        requestDto.setOrganizationName("MOSIP");
        requestDto.setPartnerDomain("FTM");

        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });

        Assert.assertEquals("KER-KMS-013", exception.getErrorCode());
    }

    @Test
    public void testUploadPartnerCertificate_NoRootCA() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(validPartnerCertData);
        requestDto.setOrganizationName("MOSIP");
        requestDto.setPartnerDomain("FTM");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-006", exception.getErrorCode());
    }

    @Test
    public void testGetPartnerCertificate_Success() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        // First upload CA and partner certificates
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(validPartnerCertData);
        partnerCertRequestDto.setOrganizationName("IITB");
        partnerCertRequestDto.setPartnerDomain("FTM");
        PartnerCertificateResponseDto uploadResponse = partnerCertService.uploadPartnerCertificate(partnerCertRequestDto);

        // Now get the certificate
        PartnerCertDownloadRequestDto downloadRequestDto = new PartnerCertDownloadRequestDto();
        downloadRequestDto.setPartnerCertId(uploadResponse.getCertificateId());

        PartnerCertDownloadResponeDto response = partnerCertService.getPartnerCertificate(downloadRequestDto);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getCertificateData());
        Assert.assertNotNull(response.getTimestamp());
    }

    @Test(expected = PartnerCertManagerException.class)
    public void testGetPartnerCertificateException() {
        PartnerCertDownloadRequestDto downloadRequestDto = new PartnerCertDownloadRequestDto();
        downloadRequestDto.setPartnerCertId("invalid-cert-id");
        partnerCertService.getPartnerCertificate(downloadRequestDto);
    }

    @Test
    public void testVerifyCertificateTrust_Success() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        // First upload CA certificate
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        // Verify certificate trust
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData(validPartnerCertData);
        requestDto.setPartnerDomain("FTM");

        CertificateTrustResponeDto response = partnerCertService.verifyCertificateTrust(requestDto);

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getStatus());
    }

    @Test
    public void testVerifyCertificateTrust_InvalidCertificate() {
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData("invalid-certificate-data");
        requestDto.setPartnerDomain("FTM");

        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            partnerCertService.verifyCertificateTrust(requestDto);
        });

        Assert.assertEquals("KER-KMS-013", exception.getErrorCode());

        requestDto.setCertificateData("");
        PartnerCertManagerException exception2 = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.verifyCertificateTrust(requestDto);
        });

        Assert.assertEquals("KER-PCM-001", exception2.getErrorCode());
    }

    @Test
    public void testUploadCACertificate_MultiplePartnerDomains() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();
        String[] domains = {"FTM", "DEVICE", "AUTH"};

        for (String domain : domains) {
            CACertificateRequestDto requestDto = new CACertificateRequestDto();
            requestDto.setCertificateData(validCACertData);
            requestDto.setPartnerDomain(domain);

            CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
            Assert.assertEquals("Upload Success.", response.getStatus());
        }
    }

    @Test
    public void testUploadPartnerCertificate_MultiplePartnerDomains() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();

        String[] domains = {"FTM", "DEVICE", "AUTH"};

        for (String domain : domains) {
            // Upload CA certificate first
            CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
            caCertRequestDto.setCertificateData(validCACertData);
            caCertRequestDto.setPartnerDomain(domain);
            partnerCertService.uploadCACertificate(caCertRequestDto);

            // Upload partner certificate
            PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
            requestDto.setCertificateData(validPartnerCertData);
            requestDto.setOrganizationName("IITB");
            requestDto.setPartnerDomain(domain);

            PartnerCertificateResponseDto response = partnerCertService.uploadPartnerCertificate(requestDto);
            Assert.assertNotNull(response.getCertificateId());
        }
    }

    @Test
    public void testUploadCACertificate_FutureDatedCertificate() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(validCACertData);
        requestDto.setPartnerDomain("FTM");

        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testUploadPartnerCertificate_OrganizationMismatch() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        // First upload CA certificate
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        // Try to upload partner certificate with wrong organization
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(validPartnerCertData);
        requestDto.setOrganizationName("WRONG_ORG");
        requestDto.setPartnerDomain("FTM");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-008", exception.getErrorCode());
    }

    @Test
    public void testGetPartnerCertificate_InvalidCertificateId() {
        PartnerCertDownloadRequestDto requestDto = new PartnerCertDownloadRequestDto();
        requestDto.setPartnerCertId("invalid-cert-id");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.getPartnerCertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-012", exception.getErrorCode());
    }

    @Test
    public void testVerifyCertificateTrust_NoTrustPath() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData(validPartnerCertData);
        requestDto.setPartnerDomain("FTM");

        CertificateTrustResponeDto response = partnerCertService.verifyCertificateTrust(requestDto);

        Assert.assertNotNull(response);
        Assert.assertFalse(response.getStatus());
    }

    @Test
    public void testUploadCACertificate_P7BFormat() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setPartnerDomain("FTM");
        requestDto.setCertificateData(validCACertData);

        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testUploadCACertificate_ExpiredCertificate() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(validCACertData);
        requestDto.setPartnerDomain("FTM");

        // Current certificate should be valid
        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testCertificateValidation_AllDomains() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();
        String[] validDomains = {"FTM", "DEVICE", "AUTH"};
        
        for (String domain : validDomains) {
            CACertificateRequestDto requestDto = new CACertificateRequestDto();
            requestDto.setCertificateData(validCACertData);
            requestDto.setPartnerDomain(domain);

            CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
            Assert.assertEquals("Upload Success.", response.getStatus());
            partnerCertService.purgeTrustStoreCache(domain);
        }
    }

    @Test
    public void testGetPartnerSignedCertificate(){
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        // First upload CA and partner certificates
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(validPartnerCertData);
        partnerCertRequestDto.setOrganizationName("IITB");
        partnerCertRequestDto.setPartnerDomain("FTM");
        PartnerCertificateResponseDto uploadResponse = partnerCertService.uploadPartnerCertificate(partnerCertRequestDto);

        // Now get the certificate
        PartnerCertDownloadRequestDto downloadRequestDto = new PartnerCertDownloadRequestDto();
        downloadRequestDto.setPartnerCertId(uploadResponse.getCertificateId());
        PartnerCertDownloadResponeDto response = partnerCertService.getPartnerCertificate(downloadRequestDto);

        Assert.assertNotNull(response.getCertificateData());
    }

    @Test
    public void testGetCACertificateTrustPath() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        // First upload CA and partner certificates
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        caCertRequestDto.setCertificateData(validPartnerCertData);
        partnerCertService.uploadCACertificate(caCertRequestDto);
        // Now get the certificate
        CACertificateStore caCertListLast = caCertificateStoreRepository.findAll().getLast();
        CACertificateTrustPathRequestDto caCertificateTrustPathRequestDto = new CACertificateTrustPathRequestDto();
        caCertificateTrustPathRequestDto.setCaCertId(caCertListLast.getCertId());

        CACertificateTrustPathResponseDto responseDto = partnerCertService.getCACertificateTrustPath(caCertificateTrustPathRequestDto);
        Assert.assertNotNull(responseDto);

        CACertificateStore caCertListFirst = caCertificateStoreRepository.findAll().getFirst();
        caCertificateTrustPathRequestDto.setCaCertId(caCertListFirst.getCertId());

        responseDto = partnerCertService.getCACertificateTrustPath(caCertificateTrustPathRequestDto);
        Assert.assertNotNull(responseDto);
    }

    @Test(expected = PartnerCertManagerException.class)
    public void testGetCACertificatePMSException() {
        CACertificateTrustPathRequestDto caCertificateTrustPathRequestDto = new CACertificateTrustPathRequestDto();
        caCertificateTrustPathRequestDto.setCaCertId("");
        partnerCertService.getCACertificateTrustPath(caCertificateTrustPathRequestDto);

        caCertificateTrustPathRequestDto.setCaCertId("invalid-cert-id");
        partnerCertService.getCACertificateTrustPath(caCertificateTrustPathRequestDto);
    }

    @Test
    public void testGetCACertificateChain() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        caCertRequestDto.setCertificateData(validPartnerCertData);
        partnerCertService.uploadCACertificate(caCertRequestDto);

        CaCertTypeListRequestDto certListRequestDto = new CaCertTypeListRequestDto();
        certListRequestDto.setPartnerDomain("FTM");
        certListRequestDto.setCaCertificateType("ROOT");
        certListRequestDto.setExcludeMosipCA(false);
        certListRequestDto.setSortByFieldName("certId");
        certListRequestDto.setSortOrder("asc");

        CaCertificateChainResponseDto responseDto = partnerCertService.getCaCertificateChain(certListRequestDto);
        Assert.assertNotNull(responseDto);
    }

    @Test
    public void testValidateCertPathWithInterCertTrust() {
        KeyPairGenerateResponseDto rootCert = keymanagerService.getCertificate("ROOT", Optional.of(""));
        String validCACertData = rootCert.getCertificate();

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto pmsCert = keymanagerService.getCertificate("PMS", Optional.of(""));
        String validPartnerCertData = pmsCert.getCertificate();

        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(validPartnerCertData);
        partnerCertRequestDto.setOrganizationName("IITB");
        partnerCertRequestDto.setPartnerDomain("FTM");
        PartnerCertificateResponseDto uploadResponse = partnerCertService.uploadPartnerCertificate(partnerCertRequestDto);

        PartnerCertDownloadRequestDto downloadRequestDto = new PartnerCertDownloadRequestDto();
        downloadRequestDto.setPartnerCertId(uploadResponse.getCertificateId());
        PartnerCertDownloadResponeDto partnerCert = partnerCertService.getPartnerCertificate(downloadRequestDto);
        X509Certificate x509Certificate = (X509Certificate) keymanagerUtil.convertToCertificate(partnerCert.getCertificateData());
        Set<X509Certificate> interCert = new HashSet<>(Collections.singleton(x509Certificate));

        boolean result = partnerCertService.validateCertificatePathWithInterCertTrust(x509Certificate, "FTM", interCert);
        Assert.assertFalse(result);
    }
}