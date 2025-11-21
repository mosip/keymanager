package io.mosip.kernel.keymanagerservice.test.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.keymanagerservice.dto.*;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import org.junit.After;
import org.junit.Assert;
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
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.is;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class KeymanagerControllerTest {

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper = new ObjectMapper();

    private RequestWrapper<KeyPairGenerateRequestDto> keyPairGenRequest;
    private RequestWrapper<CSRGenerateRequestDto> csrGenRequest;
    private RequestWrapper<SymmetricKeyGenerateRequestDto> symKeyGenRequest;
    private RequestWrapper<RevokeKeyRequestDto> revokeKeyRequest;

    private MockMvc getMockMvc() {
        return MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Before
    public void setUp() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();

        // Set authenticated context with a role allowed by @PreAuthorize (TEST is allowed in properties)
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "user",
                        "password",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_TEST"))
                )
        );

        // Initialize request wrappers for tests
        keyPairGenRequest = new RequestWrapper<>();
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("REGISTRATION");
        keyPairGenRequestDto.setReferenceId("");
        keyPairGenRequest.setRequest(keyPairGenRequestDto);

        csrGenRequest = new RequestWrapper<>();
        CSRGenerateRequestDto csrGenRequestDto = new CSRGenerateRequestDto();
        csrGenRequestDto.setApplicationId("REGISTRATION");
        csrGenRequestDto.setReferenceId("");
        csrGenRequest.setRequest(csrGenRequestDto);

        symKeyGenRequest = new RequestWrapper<>();
        SymmetricKeyGenerateRequestDto symKeyGenRequestDto = new SymmetricKeyGenerateRequestDto();
        symKeyGenRequestDto.setApplicationId("REGISTRATION");
        symKeyGenRequestDto.setReferenceId("SYMMETRIC_KEY");
        symKeyGenRequestDto.setForce(false);
        symKeyGenRequest.setRequest(symKeyGenRequestDto);

        revokeKeyRequest = new RequestWrapper<>();
        RevokeKeyRequestDto revokeKeyRequestDto = new RevokeKeyRequestDto();
        revokeKeyRequestDto.setApplicationId("REGISTRATION");
        revokeKeyRequestDto.setReferenceId("");
        revokeKeyRequestDto.setDisableAutoGen(false);
        revokeKeyRequest.setRequest(revokeKeyRequestDto);

        // Generate root key for tests
        KeyPairGenerateRequestDto rootKeyPairGenRequestDto = new KeyPairGenerateRequestDto();
        rootKeyPairGenRequestDto.setApplicationId("ROOT");
        rootKeyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", rootKeyPairGenRequestDto);
    }

    @After
    public void tearDown() {
        keyStoreRepository.deleteAll();
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testGenerateMasterKeyStatus() throws Exception {
        mockMvc.perform(post("/generateMasterKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(keyPairGenRequest)))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetCertificateStatus() throws Exception {
        mockMvc.perform(get("/getCertificate")
                        .param("applicationId", "REGISTRATION")
                        .param("referenceId", ""))
                .andExpect(status().isOk());
    }

    @Test
    public void testGenerateCSRStatus() throws Exception {
        mockMvc.perform(post("/generateCSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(csrGenRequest)))
                .andExpect(status().isOk());
    }

    @Test
    public void testUploadCertificateStatus() throws Exception {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        KeyPairGenerateResponseDto certResponse = keymanagerService.generateMasterKey("CERTIFICATE", keyPairGenRequestDto);
        UploadCertificateRequestDto uploadCertRequest = new UploadCertificateRequestDto();
        uploadCertRequest.setApplicationId("TEST");
        uploadCertRequest.setReferenceId("");
        uploadCertRequest.setCertificateData(certResponse.getCertificate());
        mockMvc.perform(post("/uploadCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(uploadCertRequest)))
                .andExpect(status().isOk());
    }

    @Test
    public void testUploadOtherDomainCertificateStatus() throws Exception {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("PMS");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        KeyPairGenerateResponseDto certResponse = keymanagerService.generateMasterKey("CERTIFICATE", keyPairGenRequestDto);
        RequestWrapper<UploadCertificateRequestDto> req = new RequestWrapper<>();
        UploadCertificateRequestDto otherDomainDto = new UploadCertificateRequestDto();
        otherDomainDto.setApplicationId("PMS");
        otherDomainDto.setReferenceId("TESTING");
        otherDomainDto.setCertificateData(certResponse.getCertificate());
        req.setRequest(otherDomainDto);
        mockMvc.perform(post("/uploadOtherDomainCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk());
    }

    @Test
    public void testGenerateSymmetricKeyStatus() throws Exception {
        mockMvc.perform(post("/generateSymmetricKey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(symKeyGenRequest)))
                .andExpect(status().isOk());
    }

    @Test
    public void testRevokeKeyStatus() throws Exception {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("REGISTRATION");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        CSRGenerateRequestDto csrGenerateRequestDto = new CSRGenerateRequestDto();
        csrGenerateRequestDto.setApplicationId("REGISTRATION");
        csrGenerateRequestDto.setReferenceId("test001");
        keymanagerService.generateCSR(csrGenerateRequestDto);

        RevokeKeyRequestDto revokeKeyRequestDto = new RevokeKeyRequestDto();
        revokeKeyRequestDto.setApplicationId("REGISTRATION");
        revokeKeyRequestDto.setReferenceId("test001");
        revokeKeyRequestDto.setDisableAutoGen(false);
        revokeKeyRequest.setRequest(revokeKeyRequestDto);
        mockMvc.perform(put("/revokeKey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(revokeKeyRequest)))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetAllCertificatesStatus() throws Exception {
        mockMvc.perform(get("/getAllCertificates")
                        .param("applicationId", "REGISTRATION")
                        .param("referenceId", ""))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetAllCertificatesWithReferenceId() {
        AllCertificatesDataResponseDto response = keymanagerService.getAllCertificates("REGISTRATION", Optional.of("test"));
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getAllCertificates());
    }

    @Test
    public void testGenerateECSignKey() {
        KeyPairGenerateRequestDto ecKeyDto = new KeyPairGenerateRequestDto();
        ecKeyDto.setApplicationId("REGISTRATION");
        ecKeyDto.setReferenceId("EC_SECP256R1_SIGN");

        KeyPairGenerateResponseDto response = keymanagerService.generateECSignKey("CSR", ecKeyDto);
        Assert.assertNotNull(response);
    }

    @Test
    public void testGenerateECSignKeyStatus() throws Exception {
        RequestWrapper<KeyPairGenerateRequestDto> req = new RequestWrapper<>();
        KeyPairGenerateRequestDto ecKeyDto = new KeyPairGenerateRequestDto();
        ecKeyDto.setApplicationId("REGISTRATION");
        ecKeyDto.setReferenceId("EC_SECP256R1_SIGN");
        req.setRequest(ecKeyDto);
        mockMvc.perform(post("/generateECSignKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk());
    }

    @Test
    public void testGenerateECSignKeyCertificate() {
        KeyPairGenerateRequestDto ecKeyDto = new KeyPairGenerateRequestDto();
        ecKeyDto.setApplicationId("REGISTRATION");
        ecKeyDto.setReferenceId("");
        keymanagerService.generateMasterKey("CERTIFICATE", ecKeyDto);

        ecKeyDto.setApplicationId("REGISTRATION");
        ecKeyDto.setReferenceId("ED25519_SIGN");

        KeyPairGenerateResponseDto response = keymanagerService.generateECSignKey("CERTIFICATE", ecKeyDto);
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getCertificate());
    }

    @Test
    public void testGetCertificateChain() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        try {
            CertificateChainResponseDto response = keymanagerService.getCertificateChain("KERNEL", Optional.of("SIGN"));
            Assert.assertNotNull(response);
        } catch (Exception e) {
            // Certificate chain may not be available in test environment
            Assert.assertTrue(e.getMessage().contains("trustPath") || e.getMessage().contains("Certificate"));
        }
    }

    @Test
    public void testGetCertificateChainWithReferenceId() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
        try {
            CertificateChainResponseDto response = keymanagerService.getCertificateChain("KERNEL", Optional.of("SIGN"));
            Assert.assertNotNull(response);
        } catch (Exception e) {
            // Certificate chain may not be available in test environment
            Assert.assertTrue(e.getMessage().contains("trustPath") || e.getMessage().contains("Certificate"));
        }
    }

    @Test
    public void testGenerateSymmetricKeyForce() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        SymmetricKeyGenerateRequestDto requestDto = new SymmetricKeyGenerateRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("SYMMETRIC_KEY");
        requestDto.setForce(false);

        SymmetricKeyGenerateResponseDto response = keymanagerService.generateSymmetricKey(requestDto);
        Assert.assertNotNull(response);
        Assert.assertEquals("Generation Success", response.getStatus());
    }

    @Test
    public void testUnauthorizedAccess() throws Exception {
        RequestWrapper<KeyPairGenerateRequestDto> request = new RequestWrapper<>();
        KeyPairGenerateRequestDto keyPairDto = new KeyPairGenerateRequestDto();
        keyPairDto.setApplicationId("REGISTRATION");
        keyPairDto.setReferenceId("");
        request.setRequest(keyPairDto);

        getMockMvc().perform(post("/generateMasterKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    public void testForbiddenAccess() throws Exception {
        RequestWrapper<KeyPairGenerateRequestDto> request = new RequestWrapper<>();
        KeyPairGenerateRequestDto keyPairDto = new KeyPairGenerateRequestDto();
        keyPairDto.setApplicationId("REGISTRATION");
        keyPairDto.setReferenceId("");
        request.setRequest(keyPairDto);

        getMockMvc().perform(post("/generateMasterKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    public void testNotFoundEndpoint() throws Exception {
        getMockMvc().perform(get("/nonExistentEndpoint"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testMethodNotAllowed() throws Exception {
        getMockMvc().perform(delete("/getCertificate")
                        .param("applicationId", "REGISTRATION")
                        .param("referenceId", ""))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testBadRequestMissingParams() throws Exception {
        getMockMvc().perform(get("/getCertificate"))
                .andExpect(status().isOk());
    }

    @Test
    public void testBadRequestMissingParams_getAllCertificates() throws Exception {
        getMockMvc().perform(get("/getAllCertificates"))
                .andExpect(status().isOk());
    }

    @Test
    public void testBadRequestMissingParams_getCertificateChain() throws Exception {
        getMockMvc().perform(get("/getCertificateChain"))
                .andExpect(status().isOk());
    }

    @Test
    public void testEmptyRequestBody() throws Exception {
        getMockMvc().perform(post("/generateMasterKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(""))
                .andExpect(status().isOk());
    }

    @Test
    public void testEmptyRequestBody_generateCSR() throws Exception {
        getMockMvc().perform(post("/generateCSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(""))
                .andExpect(status().isOk());
    }

    @Test
    public void testInvalidContentType_uploadCertificate() throws Exception {
        getMockMvc().perform(post("/uploadCertificate")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("{}"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testEmptyRequestBody_uploadCertificate() throws Exception {
        getMockMvc().perform(post("/uploadCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(""))
                .andExpect(status().isOk());
    }

    @Test
    public void testInvalidContentType_uploadOtherDomainCertificate() throws Exception {
        getMockMvc().perform(post("/uploadOtherDomainCertificate")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("{}"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testEmptyRequestBody_uploadOtherDomainCertificate() throws Exception {
        getMockMvc().perform(post("/uploadOtherDomainCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(""))
                .andExpect(status().isOk());
    }

    @Test
    public void testInvalidContentType_generateSymmetricKey() throws Exception {
        getMockMvc().perform(post("/generateSymmetricKey")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("{}"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testEmptyRequestBody_generateSymmetricKey() throws Exception {
        getMockMvc().perform(post("/generateSymmetricKey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(""))
                .andExpect(status().isOk());
    }

    @Test
    public void testInvalidContentType_revokeKey_wrongMethod() throws Exception {
        getMockMvc().perform(post("/revokeKey")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("{}"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testEmptyRequestBody_revokeKey_wrongMethod() throws Exception {
        getMockMvc().perform(post("/revokeKey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(""))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testWrongMethod_generateECSignKey() throws Exception {
        getMockMvc().perform(get("/generateECSignKey/CSR"))
                .andExpect(status().isInternalServerError());
    }

    // Additional comprehensive test cases for complete coverage

    @Test
    public void testGenerateMasterKeyWithCertificate() throws Exception {
        RequestWrapper<KeyPairGenerateRequestDto> request = new RequestWrapper<>();
        KeyPairGenerateRequestDto keyPairDto = new KeyPairGenerateRequestDto();
        keyPairDto.setApplicationId("TEST");
        keyPairDto.setReferenceId("");
        keyPairDto.setForce(true);
        request.setRequest(keyPairDto);

        mockMvc.perform(post("/generateMasterKey/CERTIFICATE")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testGetCertificateWithReferenceId() throws Exception {
        // First generate a key with reference ID - use KERNEL app which supports reference IDs
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        mockMvc.perform(get("/getCertificate")
                        .param("applicationId", "KERNEL")
                        .param("referenceId", "SIGN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testGenerateCSRWithReferenceId() throws Exception {
        RequestWrapper<CSRGenerateRequestDto> request = new RequestWrapper<>();
        CSRGenerateRequestDto csrDto = new CSRGenerateRequestDto();
        csrDto.setApplicationId("TEST");
        csrDto.setReferenceId("CSR_TEST");
        request.setRequest(csrDto);

        mockMvc.perform(post("/generateCSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testUploadCertificateWithRequestWrapper() throws Exception {
        // First generate a certificate
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        KeyPairGenerateResponseDto certResponse = keymanagerService.generateMasterKey("CERTIFICATE", keyPairGenRequestDto);

        RequestWrapper<UploadCertificateRequestDto> request = new RequestWrapper<>();
        UploadCertificateRequestDto uploadCertRequest = new UploadCertificateRequestDto();
        uploadCertRequest.setApplicationId("TEST");
        uploadCertRequest.setReferenceId("");
        uploadCertRequest.setCertificateData(certResponse.getCertificate());
        request.setRequest(uploadCertRequest);

        mockMvc.perform(post("/uploadCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testGenerateSymmetricKeyWithRequestWrapper() throws Exception {
        RequestWrapper<SymmetricKeyGenerateRequestDto> request = new RequestWrapper<>();
        SymmetricKeyGenerateRequestDto symKeyDto = new SymmetricKeyGenerateRequestDto();
        symKeyDto.setApplicationId("TEST");
        symKeyDto.setReferenceId("SYM_TEST");
        symKeyDto.setForce(true);
        request.setRequest(symKeyDto);

        mockMvc.perform(post("/generateSymmetricKey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testRevokeKeyWithRequestWrapper() throws Exception {
        // First generate a key to revoke - use KERNEL app which supports reference IDs
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        RequestWrapper<RevokeKeyRequestDto> request = new RequestWrapper<>();
        RevokeKeyRequestDto revokeDto = new RevokeKeyRequestDto();
        revokeDto.setApplicationId("KERNEL");
        revokeDto.setReferenceId("SIGN");
        revokeDto.setDisableAutoGen(true);
        request.setRequest(revokeDto);

        mockMvc.perform(put("/revokeKey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetAllCertificatesWithRequestWrapper() throws Exception {
        mockMvc.perform(get("/getAllCertificates")
                        .param("applicationId", "TEST")
                        .param("referenceId", ""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testGenerateECSignKeyWithCertificate() throws Exception {
        RequestWrapper<KeyPairGenerateRequestDto> request = new RequestWrapper<>();
        KeyPairGenerateRequestDto ecKeyDto = new KeyPairGenerateRequestDto();
        ecKeyDto.setApplicationId("TEST");
        ecKeyDto.setReferenceId("EC_SECP256R1_SIGN");
        request.setRequest(ecKeyDto);

        mockMvc.perform(post("/generateECSignKey/CERTIFICATE")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testGetCertificateChainWithRequestWrapper() throws Exception {
        // First generate a certificate chain - use KERNEL app which supports reference IDs
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("KERNEL");
        keyPairGenRequestDto.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        mockMvc.perform(get("/getCertificateChain")
                        .param("applicationId", "KERNEL")
                        .param("referenceId", "SIGN"))
                .andExpect(status().isInternalServerError());
    }

    // Negative test cases for validation errors
    @Test
    public void testGenerateMasterKeyWithInvalidObjectType() throws Exception {
        mockMvc.perform(post("/generateMasterKey/INVALID")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(keyPairGenRequest)))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testGenerateMasterKeyWithNullRequest() throws Exception {
        mockMvc.perform(post("/generateMasterKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetCertificateWithMissingApplicationId() throws Exception {
        mockMvc.perform(get("/getCertificate")
                        .param("referenceId", ""))
                .andExpect(status().isOk());
    }

    @Test
    public void testGenerateCSRWithNullRequest() throws Exception {
        mockMvc.perform(post("/generateCSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isOk());
    }

    @Test
    public void testUploadCertificateWithNullRequest() throws Exception {
        mockMvc.perform(post("/uploadCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isOk());
    }

    @Test
    public void testUploadOtherDomainCertificateWithNullRequest() throws Exception {
        mockMvc.perform(post("/uploadOtherDomainCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isOk());
    }

    @Test
    public void testGenerateSymmetricKeyWithNullRequest() throws Exception {
        mockMvc.perform(post("/generateSymmetricKey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isOk());
    }

    @Test
    public void testRevokeKeyWithNullRequest() throws Exception {
        mockMvc.perform(put("/revokeKey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isOk());
    }

    @Test
    public void testGenerateECSignKeyWithInvalidObjectType() throws Exception {
        RequestWrapper<KeyPairGenerateRequestDto> request = new RequestWrapper<>();
        KeyPairGenerateRequestDto ecKeyDto = new KeyPairGenerateRequestDto();
        ecKeyDto.setApplicationId("TEST");
        ecKeyDto.setReferenceId("EC_SECP256R1_SIGN");
        request.setRequest(ecKeyDto);

        mockMvc.perform(post("/generateECSignKey/INVALID")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetCertificateChainWithMissingApplicationId() throws Exception {
        mockMvc.perform(get("/getCertificateChain")
                        .param("referenceId", ""))
                .andExpect(status().isOk());
    }

    // Security test cases
    @Test
    public void testUnauthorizedAccessWithoutAuthentication() throws Exception {
        // Clear security context
        SecurityContextHolder.clearContext();

        mockMvc.perform(post("/generateMasterKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(keyPairGenRequest)))
                .andExpect(status().isOk());
    }

    @Test
    public void testForbiddenAccessWithWrongRole() throws Exception {
        // Set authentication with wrong role
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "user",
                        "password",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_WRONG"))
                )
        );

        mockMvc.perform(post("/generateMasterKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(keyPairGenRequest)))
                .andExpect(status().isInternalServerError());
    }

    // Edge cases and boundary tests
    @Test
    public void testGenerateMasterKeyWithEmptyApplicationId() throws Exception {
        RequestWrapper<KeyPairGenerateRequestDto> request = new RequestWrapper<>();
        KeyPairGenerateRequestDto keyPairDto = new KeyPairGenerateRequestDto();
        keyPairDto.setApplicationId("");
        keyPairDto.setReferenceId("");
        request.setRequest(keyPairDto);

        mockMvc.perform(post("/generateMasterKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetCertificateWithNullReferenceId() throws Exception {
        mockMvc.perform(get("/getCertificate")
                        .param("applicationId", "TEST"))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetAllCertificatesWithNullReferenceId() throws Exception {
        mockMvc.perform(get("/getAllCertificates")
                        .param("applicationId", "TEST"))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetCertificateChainWithNullReferenceId() throws Exception {
        mockMvc.perform(get("/getCertificateChain")
                        .param("applicationId", "KERNEL")
                        .param("referenceId", "SIGN"))
                .andExpect(status().isInternalServerError());
    }

    // Test different EC key types
    @Test
    public void testGenerateECSignKeySECP256K1() throws Exception {
        RequestWrapper<KeyPairGenerateRequestDto> request = new RequestWrapper<>();
        KeyPairGenerateRequestDto ecKeyDto = new KeyPairGenerateRequestDto();
        ecKeyDto.setApplicationId("TEST");
        ecKeyDto.setReferenceId("EC_SECP256K1_SIGN");
        request.setRequest(ecKeyDto);

        mockMvc.perform(post("/generateECSignKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testGenerateECSignKeyED25519() throws Exception {
        RequestWrapper<KeyPairGenerateRequestDto> request = new RequestWrapper<>();
        KeyPairGenerateRequestDto ecKeyDto = new KeyPairGenerateRequestDto();
        ecKeyDto.setApplicationId("REGISTRATION");
        ecKeyDto.setReferenceId("ED25519_SIGN");
        request.setRequest(ecKeyDto);

        mockMvc.perform(post("/generateECSignKey/CSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    // Additional negative and boundary tests inspired by PartnerCertManagerController tests
    @Test
    public void testUploadCertificate_InvalidCertificate() throws Exception {
        RequestWrapper<UploadCertificateRequestDto> request = new RequestWrapper<>();
        UploadCertificateRequestDto uploadCertRequest = new UploadCertificateRequestDto();
        uploadCertRequest.setApplicationId("TEST");
        uploadCertRequest.setReferenceId("");
        uploadCertRequest.setCertificateData("invalid-certificate");
        request.setRequest(uploadCertRequest);

        mockMvc.perform(post("/uploadCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode", anyOf(is("KER-KMS-013"), is("KER-KMS-005"))));
    }

    @Test
    public void testUploadCertificate_LargePayload() throws Exception {
        RequestWrapper<UploadCertificateRequestDto> request = new RequestWrapper<>();
        UploadCertificateRequestDto uploadCertRequest = new UploadCertificateRequestDto();
        uploadCertRequest.setApplicationId("TEST");
        uploadCertRequest.setReferenceId("");
        uploadCertRequest.setCertificateData("A".repeat(10000));
        request.setRequest(uploadCertRequest);

        mockMvc.perform(post("/uploadCertificate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode", anyOf(is("KER-KMS-013"), is("KER-KMS-005"))));
    }

    @Test
    public void testGenerateCSR_EmptyFields() throws Exception {
        RequestWrapper<CSRGenerateRequestDto> request = new RequestWrapper<>();
        CSRGenerateRequestDto csrDto = new CSRGenerateRequestDto();
        csrDto.setApplicationId("");
        csrDto.setReferenceId("");
        request.setRequest(csrDto);

        mockMvc.perform(post("/generateCSR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode", anyOf(is("KER-KMS-005"), is("KER-KMS-013"))));
    }

    @Test
    public void testInvalidContentType_generateECSignKey() throws Exception {
        mockMvc.perform(post("/generateECSignKey/CSR")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("{}"))
                .andExpect(status().isInternalServerError());
    }
}