package io.mosip.kernel.partnercertservice.test.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.repository.CACertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository;
import io.mosip.kernel.keymanagerservice.repository.PartnerCertificateStoreRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.partnercertservice.dto.*;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class PartnerCertManagerControllerTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private PartnerCertificateManagerService partnerCertService;

    @Autowired
    private CACertificateStoreRepository caCertificateStoreRepository;

    @Autowired
    private PartnerCertificateStoreRepository partnerCertificateStoreRepository;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper = new ObjectMapper();

    private String validCACertData = "-----BEGIN CERTIFICATE-----\n" +
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

    private String validPartnerCertData = "-----BEGIN CERTIFICATE-----\n" +
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
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "user",
                        "password",
                        Arrays.asList(
                                new SimpleGrantedAuthority("ROLE_GLOBAL_ADMIN"),
                                new SimpleGrantedAuthority("ROLE_PMS_ADMIN"),
                                new SimpleGrantedAuthority("ROLE_PMS_USER"),
                                new SimpleGrantedAuthority("ROLE_PARTNER_ADMIN")
                        )
                )
        );

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("PMS");
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
    public void testUploadCACertificate_Success() throws Exception {
        RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(validCACertData);
        requestDto.setPartnerDomain("FTM");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    public void testUploadCACertificate_InvalidCertificate() throws Exception {
        RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData("invalid-certificate");
        requestDto.setPartnerDomain("FTM");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-PCM-001"));
    }

    @Test
    public void testUploadCACertificate_InvalidDomain() throws Exception {
        RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(validCACertData);
        requestDto.setPartnerDomain("INVALID");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-PCM-011"));
    }

    @Test
    public void testUploadCACertificate_NullRequest() throws Exception {
        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-KMS-005"));
    }

    @Test
    public void testUploadCACertificate_EmptyRequest() throws Exception {
        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-KMS-005"));
    }

    @Test
    public void testUploadPartnerCertificate_DomainMissMatch() throws Exception {
        // First upload CA certificate
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        RequestWrapper<PartnerCertificateRequestDto> request = new RequestWrapper<>();
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(validPartnerCertData);
        requestDto.setOrganizationName("IITB");
        requestDto.setPartnerDomain("FTM");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadPartnerCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-PCM-008"));
    }

    @Test
    public void testUploadPartnerCertificate_InvalidCertificate() throws Exception {
        RequestWrapper<PartnerCertificateRequestDto> request = new RequestWrapper<>();
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData("invalid-certificate");
        requestDto.setOrganizationName("IITB");
        requestDto.setPartnerDomain("FTM");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadPartnerCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    public void testUploadPartnerCertificate_NullRequest() throws Exception {
        mockMvc.perform(post("/uploadPartnerCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-KMS-005"));
    }

    @Test
    public void testGetPartnerCertificate_Success() throws Exception {
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(validPartnerCertData);
        partnerCertRequestDto.setOrganizationName("Mosip");
        partnerCertRequestDto.setPartnerDomain("FTM");
        PartnerCertificateResponseDto uploadResponse = partnerCertService.uploadPartnerCertificate(partnerCertRequestDto);

        mockMvc.perform(get("/getPartnerCertificate/" + uploadResponse.getCertificateId()))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetPartnerCertificate_InvalidId() throws Exception {
        mockMvc.perform(get("/getPartnerCertificate/invalid-id"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-PCM-012"));
    }

    @Test
    public void testVerifyCertificateTrust_Success() throws Exception {
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        RequestWrapper<CertificateTrustRequestDto> request = new RequestWrapper<>();
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData(validPartnerCertData);
        requestDto.setPartnerDomain("FTM");
        request.setRequest(requestDto);

        mockMvc.perform(post("/verifyCertificateTrust")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.status").exists());
    }

    @Test
    public void testVerifyCertificateTrust_InvalidCertificate() throws Exception {
        RequestWrapper<CertificateTrustRequestDto> request = new RequestWrapper<>();
        CertificateTrustRequestDto requestDto = new CertificateTrustRequestDto();
        requestDto.setCertificateData("invalid-certificate");
        requestDto.setPartnerDomain("FTM");
        request.setRequest(requestDto);

        mockMvc.perform(post("/verifyCertificateTrust")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-KMS-013"));
    }

    @Test
    public void testGetCACertificateTrustPath_Success() throws Exception {
        // Setup: Upload CA certificate and fetch its generated ID
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        String caCertId = caCertificateStoreRepository.findAll().get(0).getCertId();

        mockMvc.perform(get("/getCACertificateTrustPath/" + caCertId))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetCACertificateChain_Success() throws Exception {
        RequestWrapper<CaCertTypeListRequestDto> request = new RequestWrapper<>();
        CaCertTypeListRequestDto requestDto = new CaCertTypeListRequestDto();
        requestDto.setPartnerDomain("FTM");
        requestDto.setCaCertificateType("ROOT");
        requestDto.setExcludeMosipCA(false);
        requestDto.setSortByFieldName("certId");
        requestDto.setSortOrder("asc");
        request.setRequest(requestDto);

        mockMvc.perform(post("/getCaCertificates")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testGetPartnerSignedCertificate_Success() throws Exception {
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(validPartnerCertData);
        partnerCertRequestDto.setOrganizationName("Mosip");
        partnerCertRequestDto.setPartnerDomain("FTM");
        PartnerCertificateResponseDto uploadResponse = partnerCertService.uploadPartnerCertificate(partnerCertRequestDto);

        mockMvc.perform(get("/getPartnerSignedCertificate/" + uploadResponse.getCertificateId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testUploadCACertificate_AllDomains() throws Exception {
        String[] domains = {"FTM", "DEVICE", "AUTH"};
        
        for (String domain : domains) {
            RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
            CACertificateRequestDto requestDto = new CACertificateRequestDto();
            requestDto.setCertificateData(validCACertData);
            requestDto.setPartnerDomain(domain);
            request.setRequest(requestDto);

            mockMvc.perform(post("/uploadCACertificate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.response.status").value("Upload Success."));
        }
    }

    // Test invalid content type
    @Test
    public void testUploadCACertificate_InvalidContentType() throws Exception {
        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("{}"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testUploadPartnerCertificate_InvalidContentType() throws Exception {
        mockMvc.perform(post("/uploadPartnerCertificate")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("{}"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testGetPartnerCertificate_WrongMethod() throws Exception {
        mockMvc.perform(post("/getPartnerCertificate/invalid"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testVerifyCertificateTrust_InvalidContentType() throws Exception {
        mockMvc.perform(post("/verifyCertificateTrust")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("{}"))
                .andExpect(status().isInternalServerError());
    }

    // Test wrong HTTP methods
    @Test
    public void testUploadCACertificate_WrongMethod() throws Exception {
        mockMvc.perform(get("/uploadCACertificate"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testUploadPartnerCertificate_WrongMethod() throws Exception {
        mockMvc.perform(get("/uploadPartnerCertificate"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testGetPartnerSignedCertificate_WrongMethod() throws Exception {
        mockMvc.perform(post("/getPartnerSignedCertificate/invalid"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testVerifyCertificateTrust_WrongMethod() throws Exception {
        mockMvc.perform(get("/verifyCertificateTrust"))
                .andExpect(status().isInternalServerError());
    }

    // Test security scenarios
    @Test
    public void testUnauthorizedAccess() throws Exception {
        SecurityContextHolder.clearContext();

        RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(validCACertData);
        requestDto.setPartnerDomain("FTM");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    public void testForbiddenAccess() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "user",
                        "password",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_WRONG"))
                )
        );

        RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData(validCACertData);
        requestDto.setPartnerDomain("FTM");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError());
    }

    // Test edge cases with empty/null fields
    @Test
    public void testUploadCACertificate_EmptyFields() throws Exception {
        RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData("");
        requestDto.setPartnerDomain("");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-KMS-005"));
    }

    @Test
    public void testUploadPartnerCertificate_EmptyFields() throws Exception {
        RequestWrapper<PartnerCertificateRequestDto> request = new RequestWrapper<>();
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData("");
        requestDto.setOrganizationName("");
        requestDto.setPartnerDomain("");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadPartnerCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-KMS-005"));
    }

    // Test large payload
    @Test
    public void testUploadCACertificate_LargePayload() throws Exception {
        RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
        CACertificateRequestDto requestDto = new CACertificateRequestDto();
        requestDto.setCertificateData("A".repeat(10000)); // Large invalid cert data
        requestDto.setPartnerDomain("FTM");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-PCM-001"));
    }

    @Test
    public void testUploadPartnerCertificate_Success() throws Exception {
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("TEST");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        RequestWrapper<PartnerCertificateRequestDto> request = new RequestWrapper<>();
        PartnerCertificateRequestDto requestDto = new PartnerCertificateRequestDto();
        requestDto.setCertificateData(validPartnerCertData);
        requestDto.setOrganizationName("Mosip");
        requestDto.setPartnerDomain("TEST");
        request.setRequest(requestDto);

        mockMvc.perform(post("/uploadPartnerCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }
}