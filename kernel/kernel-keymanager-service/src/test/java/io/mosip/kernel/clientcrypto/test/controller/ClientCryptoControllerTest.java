package io.mosip.kernel.clientcrypto.test.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import io.mosip.kernel.clientcrypto.constant.ClientType;
import io.mosip.kernel.clientcrypto.controller.ClientCryptoController;
import io.mosip.kernel.clientcrypto.dto.*;
import io.mosip.kernel.clientcrypto.service.impl.ClientCryptoFacade;
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoService;
import io.mosip.kernel.clientcrypto.test.ClientCryptoTestBootApplication;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.CryptoUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MvcResult;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.LocalDateTime;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

@SpringBootTest(classes = { ClientCryptoTestBootApplication.class })
@RunWith(SpringRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@AutoConfigureMockMvc
public class ClientCryptoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ClientCryptoController clientCryptoController;

    @Autowired
    private ClientCryptoFacade clientCryptoFacade;

    private ObjectMapper mapper;
    private byte[] testData;
    private KeyPair testKeyPair;
    private PublicKey testPublicKey;

    private static final String ID = "mosip.crypto.service";
    private static final String VERSION = "V1.0";

    @Before
    public void setUp() throws Exception {
        mapper = JsonMapper.builder().addModule(new AfterburnerModule()).build();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        testData = "Test data for client crypto operations".getBytes();
        
        // Generate test key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        testKeyPair = keyPairGenerator.generateKeyPair();
        testPublicKey = testKeyPair.getPublic();
    }

    @Test
    public void testSignData_Forbidden() throws Exception {
        RequestWrapper<TpmSignRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());
        TpmSignRequestDto requestDto = new TpmSignRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        request.setRequest(requestDto);

        mockMvc.perform(post("/cssign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithUserDetails("test")
    public void testSignDataMvc_Success() throws Exception {
        RequestWrapper<TpmSignRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());
        TpmSignRequestDto requestDto = new TpmSignRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        request.setRequest(requestDto);

        mockMvc.perform(post("/cssign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.data").isNotEmpty());
    }

    @Test
    @WithUserDetails("test")
    public void testVerifySignatureMvc_Success() throws Exception {
        // First sign the data
        RequestWrapper<TpmSignRequestDto> signRequest = new RequestWrapper<>();
        signRequest.setId(ID);
        signRequest.setVersion(VERSION);
        signRequest.setRequesttime(LocalDateTime.now());
        TpmSignRequestDto signRequestDto = new TpmSignRequestDto();
        signRequestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        signRequest.setRequest(signRequestDto);
        ResponseWrapper<TpmSignResponseDto> signResult = clientCryptoController.signData(signRequest);

        // Now verify the signature
        RequestWrapper<TpmSignVerifyRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());
        TpmSignVerifyRequestDto requestDto = new TpmSignVerifyRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setSignature(signResult.getResponse().getData());

        ClientCryptoService clientCryptoService = clientCryptoFacade.getClientSecurity();
        byte[] signingPublicKey = clientCryptoService.getSigningPublicPart();
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(signingPublicKey));
        requestDto.setClientType(ClientType.LOCAL);
        request.setRequest(requestDto);

        mockMvc.perform(post("/csverifysign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.verified").value(true));
    }

    @Test
    @WithUserDetails("test")
    public void testTpmEncryptMvc_Success() throws Exception {
        RequestWrapper<TpmCryptoRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(ClientType.LOCAL);
        request.setRequest(requestDto);

        mockMvc.perform(post("/tpmencrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.value").isNotEmpty());
    }

    @Test
    @WithUserDetails("test")
    public void testTpmDecryptMvc_Success() throws Exception {
        // First encrypt the data
        RequestWrapper<TpmCryptoRequestDto> encryptRequest = new RequestWrapper<>();
        encryptRequest.setId(ID);
        encryptRequest.setVersion(VERSION);
        encryptRequest.setRequesttime(LocalDateTime.now());
        TpmCryptoRequestDto encryptRequestDto = new TpmCryptoRequestDto();
        encryptRequestDto.setValue(CryptoUtil.encodeToURLSafeBase64(testData));

        ClientCryptoService clientCryptoService = clientCryptoFacade.getClientSecurity();
        byte[] encryptionPublicKey = clientCryptoService.getEncryptionPublicPart();
        encryptRequestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(encryptionPublicKey));
        encryptRequestDto.setClientType(null);
        encryptRequest.setRequest(encryptRequestDto);
        ResponseWrapper<TpmCryptoResponseDto> encryptResult = clientCryptoController.tpmEncrypt(encryptRequest);

        // Now decrypt the data
        RequestWrapper<TpmCryptoRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue(encryptResult.getResponse().getValue());
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(encryptionPublicKey));
        request.setRequest(requestDto);

        mockMvc.perform(post("/tpmdecrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.value").isNotEmpty());
    }

    @Test
    @WithUserDetails("test")
    public void testGetSigningPublicKeyMvc_Success() throws Exception {
        RequestWrapper<PublicKeyRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());
        PublicKeyRequestDto requestDto = new PublicKeyRequestDto();
        requestDto.setServerProfile("test");
        request.setRequest(requestDto);

        mockMvc.perform(post("/tpmsigning/publickey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.publicKey").isNotEmpty());
    }

    @Test
    @WithUserDetails("test")
    public void testGetEncPublicKeyMvc_Success() throws Exception {
        RequestWrapper<PublicKeyRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());
        PublicKeyRequestDto requestDto = new PublicKeyRequestDto();
        requestDto.setServerProfile("test");
        request.setRequest(requestDto);

        mockMvc.perform(post("/tpmencryption/publickey")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.publicKey").isNotEmpty());
    }

    @Test
    @WithUserDetails("test")
    public void testVerifySignature_Success() throws Exception {
        // First sign the data
        RequestWrapper<TpmSignRequestDto> signRequest = new RequestWrapper<>();
        signRequest.setId(ID);
        signRequest.setVersion(VERSION);
        signRequest.setRequesttime(LocalDateTime.now());
        TpmSignRequestDto signRequestDto = new TpmSignRequestDto();
        signRequestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        signRequest.setRequest(signRequestDto);
        ResponseWrapper<TpmSignResponseDto> signResult = clientCryptoController.signData(signRequest);

        // Now verify the signature
        RequestWrapper<TpmSignVerifyRequestDto> request = new RequestWrapper<>();
        request.setId(ID);
        request.setVersion(VERSION);
        request.setRequesttime(LocalDateTime.now());
        TpmSignVerifyRequestDto requestDto = new TpmSignVerifyRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setSignature(signResult.getResponse().getData());

        ClientCryptoService clientCryptoService = clientCryptoFacade.getClientSecurity();
        byte[] signingPublicKey = clientCryptoService.getSigningPublicPart();
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(signingPublicKey));
        requestDto.setClientType(ClientType.LOCAL);
        request.setRequest(requestDto);

        MvcResult result = mockMvc.perform(post("/csverifysign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andReturn();

        Assert.assertTrue(result.getResponse().getContentAsString().contains("verified"));
    }
}