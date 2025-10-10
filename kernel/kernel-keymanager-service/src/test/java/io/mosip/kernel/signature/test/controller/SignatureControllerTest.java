package io.mosip.kernel.signature.test.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.signature.dto.*;
import io.mosip.kernel.signature.service.CoseSignatureService;
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
public class SignatureControllerTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private CoseSignatureService coseSignatureService;

    private MockMvc mockMvc;
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    private MockMvc getMockMvc() {
        return MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Before
    public void setUp() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "user",
                        "password",
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_TEST"))
                )
        );

        KeyPairGenerateRequestDto rootKeyPairGenRequestDto = new KeyPairGenerateRequestDto();
        rootKeyPairGenRequestDto.setApplicationId("ROOT");
        rootKeyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", rootKeyPairGenRequestDto);
    }

    // ===== CoseSignController endpoints =====

    @Test
    public void testCoseSign1_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("TEST");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<CoseSignRequestDto> req = new RequestWrapper<>();
        CoseSignRequestDto dto = new CoseSignRequestDto();
        dto.setApplicationId("TEST");
        dto.setReferenceId("");
        dto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        req.setRequest(dto);

        mockMvc.perform(post("/coseSign1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testCoseVerify1_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("TEST");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        CoseSignRequestDto signDto = new CoseSignRequestDto();
        signDto.setApplicationId("TEST");
        signDto.setReferenceId("");
        signDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto signed = coseSignatureService.coseSign1(signDto);

        RequestWrapper<CoseSignVerifyRequestDto> req = new RequestWrapper<>();
        CoseSignVerifyRequestDto verifyDto = new CoseSignVerifyRequestDto();
        verifyDto.setApplicationId("TEST");
        verifyDto.setReferenceId("");
        verifyDto.setCoseSignedData(signed.getSignedData());
        req.setRequest(verifyDto);

        mockMvc.perform(post("/coseVerify1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testCwtSign_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("ID_REPO");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<CWTSignRequestDto> req = new RequestWrapper<>();
        CWTSignRequestDto dto = new CWTSignRequestDto();
        dto.setApplicationId("ID_REPO");
        dto.setReferenceId("");
        dto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        req.setRequest(dto);

        mockMvc.perform(post("/cwtSign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testCwtVerify_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("ID_REPO");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        CWTSignRequestDto signDto = new CWTSignRequestDto();
        signDto.setApplicationId("ID_REPO");
        signDto.setReferenceId("");
        signDto.setPayload("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        CoseSignResponseDto signed = coseSignatureService.cwtSign(signDto);

        RequestWrapper<CWTVerifyRequestDto> req = new RequestWrapper<>();
        CWTVerifyRequestDto verifyDto = new CWTVerifyRequestDto();
        verifyDto.setApplicationId("ID_REPO");
        verifyDto.setReferenceId("");
        verifyDto.setCoseSignedData(signed.getSignedData());
        req.setRequest(verifyDto);

        mockMvc.perform(post("/cwtVerify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    // ===== SignatureController endpoints =====

    @Test
    public void testSign_statusOk() throws Exception {
        RequestWrapper<SignRequestDto> req = new RequestWrapper<>();
        SignRequestDto dto = new SignRequestDto();
        dto.setData("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        req.setRequest(dto);

        mockMvc.perform(post("/sign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testValidate_statusOk() throws Exception {
        // Generate KERNEL/SIGN key for validation
        KeyPairGenerateRequestDto kernelKey = new KeyPairGenerateRequestDto();
        kernelKey.setApplicationId("KERNEL");
        kernelKey.setReferenceId("SIGN");
        keymanagerService.generateMasterKey("CSR", kernelKey);

        // First sign the data to get a valid signature
        RequestWrapper<SignRequestDto> signReq = new RequestWrapper<>();
        SignRequestDto signDto = new SignRequestDto();
        signDto.setData("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        signReq.setRequest(signDto);
        
        String signResponse = mockMvc.perform(post("/sign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signReq)))
                .andReturn().getResponse().getContentAsString();
        
        String signature = objectMapper.readTree(signResponse).path("response").path("data").asText();

        RequestWrapper<TimestampRequestDto> req = new RequestWrapper<>();
        TimestampRequestDto dto = new TimestampRequestDto();
        dto.setData("eyAibW9kdWxlIjogImtleW1hbmFnZXIiLCAicHVycG9zZSI6ICJ0ZXN0IGNhc2UiIH0");
        dto.setSignature(signature);
        dto.setTimestamp(io.mosip.kernel.core.util.DateUtils.getUTCCurrentDateTime());
        req.setRequest(dto);

        mockMvc.perform(post("/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().is2xxSuccessful());
    }

    @Test
    public void testPdfSign_statusHandled() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("TEST");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<PDFSignatureRequestDto> req = new RequestWrapper<>();
        PDFSignatureRequestDto dto = new PDFSignatureRequestDto();
        dto.setApplicationId("TEST");
        dto.setReferenceId("");
        dto.setData("ZHVtbXkgcGRmIGNvbnRlbnQ=");
        dto.setTimeStamp(io.mosip.kernel.core.util.DateUtils.getUTCCurrentDateTimeString());
        dto.setPageNumber(1);
        dto.setLowerLeftX(10);
        dto.setLowerLeftY(10);
        dto.setUpperRightX(100);
        dto.setUpperRightY(100);
        req.setRequest(dto);

        mockMvc.perform(post("/pdf/sign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().is2xxSuccessful());
    }

    @Test
    public void testJwtSign_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("TEST");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<JWTSignatureRequestDto> req = new RequestWrapper<>();
        JWTSignatureRequestDto dto = new JWTSignatureRequestDto();
        dto.setApplicationId("TEST");
        dto.setReferenceId("");
        dto.setDataToSign("eyJ0ZXN0IjoiZGF0YSJ9");
        dto.setIncludePayload(true);
        req.setRequest(dto);

        mockMvc.perform(post("/jwtSign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testJwtVerify_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("TEST");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<JWTSignatureRequestDto> signReq = new RequestWrapper<>();
        JWTSignatureRequestDto signDto = new JWTSignatureRequestDto();
        signDto.setApplicationId("TEST");
        signDto.setReferenceId("");
        signDto.setDataToSign("eyJ0ZXN0IjoiZGF0YSJ9");
        signDto.setIncludePayload(true);
        signReq.setRequest(signDto);
        String signed = mockMvc.perform(post("/jwtSign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signReq)))
                .andReturn().getResponse().getContentAsString();

        String jwt = objectMapper.readTree(signed).path("response").path("jwtSignedData").asText();

        RequestWrapper<JWTSignatureVerifyRequestDto> req = new RequestWrapper<>();
        JWTSignatureVerifyRequestDto dto = new JWTSignatureVerifyRequestDto();
        dto.setApplicationId("TEST");
        dto.setReferenceId("");
        dto.setJwtSignatureData(jwt);
        req.setRequest(dto);

        mockMvc.perform(post("/jwtVerify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testJwsSign_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("TEST");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<JWSSignatureRequestDto> req = new RequestWrapper<>();
        JWSSignatureRequestDto dto = new JWSSignatureRequestDto();
        dto.setApplicationId("TEST");
        dto.setReferenceId("");
        dto.setDataToSign("eyJ0ZXN0IjoiZGF0YSJ9");
        dto.setIncludePayload(true);
        dto.setValidateJson(true);
        req.setRequest(dto);

        mockMvc.perform(post("/jwsSign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testSignV2_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("TEST");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<SignRequestDtoV2> req = new RequestWrapper<>();
        SignRequestDtoV2 dto = new SignRequestDtoV2();
        dto.setApplicationId("TEST");
        dto.setReferenceId("");
        dto.setDataToSign("dGVzdCBkYXRh");
        dto.setSignAlgorithm("PS256");
        dto.setResponseEncodingFormat("base64url");
        req.setRequest(dto);

        mockMvc.perform(post("/signV2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testSignRawData_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("TEST");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<SignRequestDtoV2> req = new RequestWrapper<>();
        SignRequestDtoV2 dto = new SignRequestDtoV2();
        dto.setApplicationId("TEST");
        dto.setReferenceId("");
        dto.setDataToSign("dGVzdCBkYXRh");
        dto.setSignAlgorithm("PS256");
        req.setRequest(dto);

        mockMvc.perform(post("/signRawData")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testJwtSignV2_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("TEST");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<JWTSignatureRequestDtoV2> req = new RequestWrapper<>();
        JWTSignatureRequestDtoV2 dto = new JWTSignatureRequestDtoV2();
        dto.setApplicationId("TEST");
        dto.setReferenceId("");
        dto.setDataToSign("eyJ0ZXN0IjoiZGF0YSJ9");
        dto.setIncludePayload(true);
        req.setRequest(dto);

        mockMvc.perform(post("/jwtSign/v2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testJwsSignV2_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("BASE");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<JWSSignatureRequestDtoV2> req = new RequestWrapper<>();
        JWSSignatureRequestDtoV2 dto = new JWSSignatureRequestDtoV2();
        dto.setApplicationId("BASE");
        dto.setReferenceId("");
        dto.setDataToSign("eyJ0ZXN0IjoiZGF0YSJ9");
        dto.setIncludePayload(true);
        dto.setValidateJson(false);
        req.setRequest(dto);

        mockMvc.perform(post("/jwsSign/v2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }

    @Test
    public void testJwtVerifyV2_statusOk() throws Exception {
        KeyPairGenerateRequestDto key = new KeyPairGenerateRequestDto();
        key.setApplicationId("RESIDENT");
        key.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", key);

        RequestWrapper<JWTSignatureRequestDtoV2> signReq = new RequestWrapper<>();
        JWTSignatureRequestDtoV2 signDto = new JWTSignatureRequestDtoV2();
        signDto.setApplicationId("RESIDENT");
        signDto.setReferenceId("");
        signDto.setDataToSign("eyJ0ZXN0IjoiZGF0YSJ9");
        signDto.setIncludePayload(true);
        signDto.setIncludeCertificateChain(true);
        signReq.setRequest(signDto);
        String signed = mockMvc.perform(post("/jwtSign/v2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signReq)))
                .andReturn().getResponse().getContentAsString();

        String jwt = objectMapper.readTree(signed).path("response").path("jwtSignedData").asText();

        RequestWrapper<JWTSignatureVerifyRequestDto> req = new RequestWrapper<>();
        JWTSignatureVerifyRequestDto dto = new JWTSignatureVerifyRequestDto();
        dto.setApplicationId("RESIDENT");
        dto.setReferenceId("");
        dto.setJwtSignatureData(jwt);
        dto.setValidateTrust(false);
        req.setRequest(dto);

        mockMvc.perform(post("/jwtVerify/v2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response").exists());
    }
}
