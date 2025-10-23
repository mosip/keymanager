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
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoManagerService;
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoService;
import io.mosip.kernel.clientcrypto.test.ClientCryptoTestBootApplication;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.CryptoUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.junit.Assert.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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
    private ClientCryptoManagerService clientCryptoManagerService;

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
    public void testSignData_Success() {
        RequestWrapper<TpmSignRequestDto> request = new RequestWrapper<>();
        TpmSignRequestDto requestDto = new TpmSignRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        request.setRequest(requestDto);

        ResponseWrapper<TpmSignResponseDto> result = clientCryptoController.signData(request);

        assertNotNull(result);
        assertNotNull(result.getResponse());
        assertNotNull(result.getResponse().getData());
        assertFalse(result.getResponse().getData().isEmpty());
    }

    @Test
    public void testVerifySignature_Success() {
        RequestWrapper<TpmSignRequestDto> signRequest = new RequestWrapper<>();
        TpmSignRequestDto signRequestDto = new TpmSignRequestDto();
        signRequestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        signRequest.setRequest(signRequestDto);
        ResponseWrapper<TpmSignResponseDto> signResult = clientCryptoController.signData(signRequest);

        RequestWrapper<TpmSignVerifyRequestDto> request = new RequestWrapper<>();
        TpmSignVerifyRequestDto requestDto = new TpmSignVerifyRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setSignature(signResult.getResponse().getData());

        ClientCryptoService clientCryptoService = clientCryptoFacade.getClientSecurity();
        assertNotNull(clientCryptoService);
        byte[] signingPublicKey = clientCryptoService.getSigningPublicPart();
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(signingPublicKey));
        requestDto.setClientType(ClientType.LOCAL);
        request.setRequest(requestDto);

        ResponseWrapper<TpmSignVerifyResponseDto> result = clientCryptoController.verifySignature(request);

        assertNotNull(result);
        assertNotNull(result.getResponse());
        assertTrue(result.getResponse().isVerified());
    }

    @Test(expected = io.mosip.kernel.clientcrypto.exception.ClientCryptoException.class)
    public void testVerifySignature_WithNullClientType() {
        RequestWrapper<TpmSignVerifyRequestDto> request = new RequestWrapper<>();
        TpmSignVerifyRequestDto requestDto = new TpmSignVerifyRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setSignature(CryptoUtil.encodeToURLSafeBase64("test signature".getBytes()));
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(null);
        request.setRequest(requestDto);
        clientCryptoController.verifySignature(request);
    }

    @Test
    public void testTpmEncrypt_Success() {
        RequestWrapper<TpmCryptoRequestDto> request = new RequestWrapper<>();
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(ClientType.LOCAL);
        request.setRequest(requestDto);

        ResponseWrapper<TpmCryptoResponseDto> result = clientCryptoController.tpmEncrypt(request);

        assertNotNull(result);
        assertNotNull(result.getResponse());
        assertNotNull(result.getResponse().getValue());
        assertFalse(result.getResponse().getValue().isEmpty());
    }

    @Test
    public void testTpmEncrypt_WithAndroidClientType() {
        RequestWrapper<TpmCryptoRequestDto> request = new RequestWrapper<>();
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(ClientType.ANDROID);
        request.setRequest(requestDto);

        ResponseWrapper<TpmCryptoResponseDto> result = clientCryptoController.tpmEncrypt(request);

        assertNotNull(result);
        assertNotNull(result.getResponse());
        assertNotNull(result.getResponse().getValue());
        assertFalse(result.getResponse().getValue().isEmpty());
    }

    @Test
    public void testTpmEncrypt_WithNullClientType() {
        RequestWrapper<TpmCryptoRequestDto> request = new RequestWrapper<>();
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(null);
        request.setRequest(requestDto);

        ResponseWrapper<TpmCryptoResponseDto> result = clientCryptoController.tpmEncrypt(request);

        assertNotNull(result);
        assertNotNull(result.getResponse());
        assertNotNull(result.getResponse().getValue());
        assertFalse(result.getResponse().getValue().isEmpty());
    }

    @Test
    public void testTpmDecrypt_Success() {
        RequestWrapper<TpmCryptoRequestDto> encryptRequest = new RequestWrapper<>();
        TpmCryptoRequestDto encryptRequestDto = new TpmCryptoRequestDto();
        encryptRequestDto.setValue(CryptoUtil.encodeToURLSafeBase64(testData));

        ClientCryptoService clientCryptoService = clientCryptoFacade.getClientSecurity();
        assertNotNull(clientCryptoService);
        byte[] encryptionPublicKey = clientCryptoService.getEncryptionPublicPart();
        encryptRequestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(encryptionPublicKey));
        encryptRequestDto.setClientType(null);
        encryptRequest.setRequest(encryptRequestDto);
        ResponseWrapper<TpmCryptoResponseDto> encryptResult = clientCryptoController.tpmEncrypt(encryptRequest);

        RequestWrapper<TpmCryptoRequestDto> request = new RequestWrapper<>();
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue(encryptResult.getResponse().getValue());
        request.setRequest(requestDto);

        ResponseWrapper<TpmCryptoResponseDto> result = clientCryptoController.tpmDecrypt(request);

        assertNotNull(result);
        assertNotNull(result.getResponse());
        assertNotNull(result.getResponse().getValue());
    }


    @Test
    public void testGetSigningPublicKey_Success() {
        RequestWrapper<PublicKeyRequestDto> request = new RequestWrapper<>();
        PublicKeyRequestDto requestDto = new PublicKeyRequestDto();
        request.setRequest(requestDto);

        ResponseWrapper<PublicKeyResponseDto> result = clientCryptoController.getSigningPublicKey(request);

        assertNotNull(result);
        assertNotNull(result.getResponse());
        assertNotNull(result.getResponse().getPublicKey());
        assertFalse(result.getResponse().getPublicKey().isEmpty());
    }

    @Test
    public void testGetEncPublicKey_Success() {
        RequestWrapper<PublicKeyRequestDto> request = new RequestWrapper<>();
        PublicKeyRequestDto requestDto = new PublicKeyRequestDto();
        request.setRequest(requestDto);

        ResponseWrapper<PublicKeyResponseDto> result = clientCryptoController.getEncPublicKey(request);

        assertNotNull(result);
        assertNotNull(result.getResponse());
        assertNotNull(result.getResponse().getPublicKey());
        assertFalse(result.getResponse().getPublicKey().isEmpty());
    }

    @Test
    public void testSignData_Forbidden() throws Exception {
        RequestWrapper<TpmSignRequestDto> request = new RequestWrapper<>();
        TpmSignRequestDto requestDto = new TpmSignRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        request.setRequest(requestDto);

        mockMvc.perform(post("/cssign")
                        .contentType("text/plain")
                        .content(mapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }
}