package io.mosip.kernel.cryptomanager.test.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.cryptomanager.dto.*;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
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
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.LocalDateTime;
import java.util.Arrays;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class CryptomanagerControllerTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    @Autowired
    private CryptomanagerService cryptomanagerService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
    }

    private static final String ID = "mosip.crypto.service";
    private static final String VERSION = "V1.0";

    @Before
    public void setUp() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "user",
                        "password",
                        Arrays.asList(
                                new SimpleGrantedAuthority("ROLE_TEST"),
                                new SimpleGrantedAuthority("ROLE_INDIVIDUAL"),
                                new SimpleGrantedAuthority("ROLE_ID_AUTHENTICATION")
                        )
                )
        );

        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
    }

    @After
    public void tearDown() {
        keyStoreRepository.deleteAll();
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testEncrypt_Success() throws Exception {
        RequestWrapper<CryptomanagerRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());

        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("ref");
        requestDto.setTimeStamp(LocalDateTime.now());
        requestDto.setData("dGVzdCBjYXNlIGRhdGEgZm9yIGNyeXB0b21hbmFnZXI");
        request.setRequest(requestDto);

        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.data").isNotEmpty());
    }

    @Test
    public void testDecrypt_Success() throws Exception {
        RequestWrapper<CryptomanagerRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());

        CryptomanagerRequestDto encryptRequestDto = new CryptomanagerRequestDto();
        encryptRequestDto.setApplicationId("TEST");
        encryptRequestDto.setReferenceId("ref");
        encryptRequestDto.setData("dGVzdCBjYXNlIGRhdGEgZm9yIGNyeXB0b21hbmFnZXI");
        CryptomanagerResponseDto encryptResponse = cryptomanagerService.encrypt(encryptRequestDto);

        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("ref");
        requestDto.setTimeStamp(LocalDateTime.now());
        requestDto.setData(encryptResponse.getData());
        request.setRequest(requestDto);

        mockMvc.perform(post("/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.data").value("dGVzdCBjYXNlIGRhdGEgZm9yIGNyeXB0b21hbmFnZXI"));
    }

    @Test
    public void testEncryptWithPin_Success() throws Exception {
        RequestWrapper<CryptoWithPinRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());

        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setData("dGVzdCBjYXNlIGRhdGEgZm9yIGNyeXB0b21hbmFnZXI");
        requestDto.setUserPin("123456");
        request.setRequest(requestDto);

        mockMvc.perform(post("/encryptWithPin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.data").isNotEmpty());
    }

    @Test
    public void testDecryptWithPin_Success() throws Exception {
        RequestWrapper<CryptoWithPinRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());

        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setData("dGVzdCBjYXNlIGRhdGEgZm9yIGNyeXB0b21hbmFnZXI");
        requestDto.setUserPin("123456");
        request.setRequest(requestDto);

        CryptoWithPinResponseDto encryptResponse = cryptomanagerService.encryptWithPin(requestDto);
        requestDto.setData(encryptResponse.getData());

        mockMvc.perform(post("/decryptWithPin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.data").value("dGVzdCBjYXNlIGRhdGEgZm9yIGNyeXB0b21hbmFnZXI"));
    }

    @Test
    public void testEncrypt_InvalidRequest() throws Exception {
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-KMS-005"));
    }

    @Test
    public void testEncrypt_WithSaltAndAad() throws Exception {
        RequestWrapper<CryptomanagerRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());

        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("ref");
        requestDto.setTimeStamp(LocalDateTime.now());
        requestDto.setData("dGVzdCBjYXNlIGRhdGEgZm9yIGNyeXB0b21hbmFnZXI");
        requestDto.setSalt("IWdCK2J3S2xQTD1S");
        requestDto.setAad("dzhENWsyczlMcVpwN240WA");
        request.setRequest(requestDto);

        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.data").isNotEmpty());
    }

    @Test
    public void testDecrypt_InvalidRequest() throws Exception {
        mockMvc.perform(post("/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").value("KER-KMS-005"));
    }

    @Test
    public void testJwtEncrypt() throws Exception {
        RequestWrapper<JWTEncryptRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());

        JWTEncryptRequestDto requestDto = new JWTEncryptRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("jwt");
        requestDto.setData("eyAiZGF0YSI6ICJ0ZXN0IGRhdGEgZm9yIGNyeXB0b21hbmFnZXIiIH0");
        request.setRequest(requestDto);

        mockMvc.perform(post("/jwtEncrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.data").isNotEmpty());
    }

    @Test
    public void testJwtDecrypt() throws Exception {
        RequestWrapper<JWTDecryptRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());

        JWTEncryptRequestDto encryptRequestDto = new JWTEncryptRequestDto();
        encryptRequestDto.setApplicationId("TEST");
        encryptRequestDto.setReferenceId("jwtDecrypt");
        encryptRequestDto.setData("eyAiZGF0YSI6ICJ0ZXN0IGRhdGEgZm9yIGNyeXB0b21hbmFnZXIiIH0");
        JWTCipherResponseDto encryptResponse = cryptomanagerService.jwtEncrypt(encryptRequestDto);

        JWTDecryptRequestDto requestDto = new JWTDecryptRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("jwtDecrypt");
        requestDto.setEncData(encryptResponse.getData());
        request.setRequest(requestDto);

        mockMvc.perform(post("/jwtDecrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.data").value("eyAiZGF0YSI6ICJ0ZXN0IGRhdGEgZm9yIGNyeXB0b21hbmFnZXIiIH0"));
    }

    @Test
    public void testInvalidContentType() throws Exception {
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("{}")
                        .with(csrf()))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testWrongHttpMethod() throws Exception {
        mockMvc.perform(post("/nonExistentEndpoint")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .with(csrf()))
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void testEncrypt_InvalidApplicationId() throws Exception {
        RequestWrapper<CryptomanagerRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());

        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("INVALID_APP");
        requestDto.setReferenceId("");
        requestDto.setTimeStamp(LocalDateTime.now());
        requestDto.setData("dGVzdCBjYXNlIGRhdGEgZm9yIGNyeXB0b21hbmFnZXI");
        request.setRequest(requestDto);

        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errors[0].errorCode").exists());
    }

    @Test
    public void testGenerateArgon2() throws Exception {
        RequestWrapper<Argon2GenerateHashRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());

        Argon2GenerateHashRequestDto requestDto = new Argon2GenerateHashRequestDto();
        requestDto.setInputData("testdataforargon2hashing");
        requestDto.setSalt("randomsaltvalue");

        mockMvc.perform(post("/generateArgon2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isInternalServerError());
    }
}