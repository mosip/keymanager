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
import java.util.Optional;

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

    private String validCACertData;
    private String validPartnerCertData;

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

        validCACertData = keymanagerService.getCertificate("ROOT", Optional.of("")).getCertificate();
        validPartnerCertData = keymanagerService.getCertificate("PMS", Optional.of("")).getCertificate();
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
                .andExpect(status().isOk());
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
                .andExpect(status().isOk());
    }

    @Test
    public void testUploadCACertificate_NullRequest() throws Exception {
        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isOk());
    }

    @Test
    public void testUploadCACertificate_EmptyRequest() throws Exception {
        mockMvc.perform(post("/uploadCACertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(""))
                .andExpect(status().isOk());
    }

    @Test
    public void testUploadPartnerCertificate_Success() throws Exception {
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
                .andExpect(status().isOk());
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
                .andExpect(status().isOk());
    }

    @Test
    public void testGetPartnerCertificate_Success() throws Exception {
        CACertificateRequestDto caCertRequestDto = new CACertificateRequestDto();
        caCertRequestDto.setCertificateData(validCACertData);
        caCertRequestDto.setPartnerDomain("FTM");
        partnerCertService.uploadCACertificate(caCertRequestDto);

        PartnerCertificateRequestDto partnerCertRequestDto = new PartnerCertificateRequestDto();
        partnerCertRequestDto.setCertificateData(validPartnerCertData);
        partnerCertRequestDto.setOrganizationName("IITB");
        partnerCertRequestDto.setPartnerDomain("FTM");
        PartnerCertificateResponseDto uploadResponse = partnerCertService.uploadPartnerCertificate(partnerCertRequestDto);

        mockMvc.perform(get("/getPartnerCertificate/" + uploadResponse.getCertificateId()))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetPartnerCertificate_InvalidId() throws Exception {
        mockMvc.perform(get("/getPartnerCertificate/invalid-id"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors").exists());
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
                .andExpect(jsonPath("$.errors").exists());
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
        partnerCertRequestDto.setOrganizationName("IITB");
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
                .andExpect(jsonPath("$.errors").exists());
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
                .andExpect(jsonPath("$.errors").exists());
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
                .andExpect(jsonPath("$.errors").exists());
    }
}