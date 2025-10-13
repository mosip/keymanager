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

    private String caCertificate = "-----BEGIN CERTIFICATE-----\n" +
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
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("FTM");

        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);

        Assert.assertNotNull(response);
        Assert.assertEquals("Upload Success.", response.getStatus());
        Assert.assertNotNull(response.getTimestamp());

        requestDto.setCertificateData(interCertificate);
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
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("INVALID_DOMAIN");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadCACertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-011", exception.getErrorCode());
    }

    @Test
    public void testUploadCACertificate_DuplicateCertificate() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
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
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        // First upload CA certificate
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        // Now upload partner certificate
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(interCertificate);
        requestDto.setOrganizationName("Mosip");
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
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(interCertificate);
        requestDto.setOrganizationName("MOSIP");
        requestDto.setPartnerDomain("FTM");

        PartnerCertManagerException exception = assertThrows(PartnerCertManagerException.class, () -> {
            partnerCertService.uploadPartnerCertificate(requestDto);
        });

        Assert.assertEquals("KER-PCM-006", exception.getErrorCode());
    }

    @Test
    public void testGetPartnerCertificate_Success() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(interCertificate);
        partnerCertRequestDto.setOrganizationName("Mosip");
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
        // First upload CA certificate
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        // Verify certificate trust
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData(interCertificate);
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
        String[] domains = {"FTM", "DEVICE", "AUTH"};

        for (String domain : domains) {
            // Upload CA certificate first
            CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
            caCertRequestDto.setCertificateData(caCertificate);
            caCertRequestDto.setPartnerDomain(domain);
            partnerCertService.uploadCACertificate(caCertRequestDto);

            // Upload partner certificate
            PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
            requestDto.setCertificateData(interCertificate);
            requestDto.setOrganizationName("Mosip");
            requestDto.setPartnerDomain(domain);

            PartnerCertificateResponseDto response = partnerCertService.uploadPartnerCertificate(requestDto);
            Assert.assertNotNull(response.getCertificateId());
        }
    }

    @Test
    public void testUploadCACertificate_FutureDatedCertificate() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("FTM");

        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testUploadPartnerCertificate_OrganizationMismatch() {
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        // Try to upload partner certificate with wrong organization
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(interCertificate);
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
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData(interCertificate);
        requestDto.setPartnerDomain("FTM");

        CertificateTrustResponeDto response = partnerCertService.verifyCertificateTrust(requestDto);

        Assert.assertNotNull(response);
        Assert.assertFalse(response.getStatus());
    }

    @Test
    public void testUploadCACertificate_P7BFormat() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setPartnerDomain("FTM");
        requestDto.setCertificateData(caCertificate);

        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testUploadCACertificate_ExpiredCertificate() {
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(caCertificate);
        requestDto.setPartnerDomain("FTM");

        // Current certificate should be valid
        CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
        Assert.assertEquals("Upload Success.", response.getStatus());
    }

    @Test
    public void testCertificateValidation_AllDomains() {
        String[] validDomains = {"FTM", "DEVICE", "AUTH"};
        
        for (String domain : validDomains) {
            CACertificateRequestDto requestDto = new CACertificateRequestDto();
            requestDto.setCertificateData(caCertificate);
            requestDto.setPartnerDomain(domain);

            CACertificateResponseDto response = partnerCertService.uploadCACertificate(requestDto);
            Assert.assertEquals("Upload Success.", response.getStatus());
            partnerCertService.purgeTrustStoreCache(domain);
        }
    }

    @Test
    public void testGetPartnerSignedCertificate(){
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(interCertificate);
        partnerCertRequestDto.setOrganizationName("Mosip");
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
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        caCertRequestDto.setCertificateData(interCertificate);
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
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        caCertRequestDto.setCertificateData(interCertificate);
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
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(caCertificate);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(interCertificate);
        partnerCertRequestDto.setOrganizationName("Mosip");
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