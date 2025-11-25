package io.mosip.kernel.clientcrypto.test.service;

import static org.junit.jupiter.api.Assertions.*;

import io.mosip.kernel.clientcrypto.constant.ClientType;
import io.mosip.kernel.clientcrypto.dto.*;
import io.mosip.kernel.clientcrypto.exception.ClientCryptoException;
import io.mosip.kernel.clientcrypto.service.impl.AndroidClientCryptoServiceImpl;
import io.mosip.kernel.clientcrypto.service.impl.ClientCryptoFacade;
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoManagerService;
import io.mosip.kernel.clientcrypto.test.ClientCryptoTestBootApplication;
import io.mosip.kernel.core.util.CryptoUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

@SpringBootTest(classes = { ClientCryptoTestBootApplication.class })
@RunWith(SpringRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class ClientCryptoServiceTest {

    @Autowired
    private ClientCryptoFacade clientCryptoFacade;

    @Autowired
    private ClientCryptoManagerService clientCryptoManagerService;

    private byte[] testData;
    private KeyPair testKeyPair;
    private PublicKey testPublicKey;

    @Before
    public void setUp() throws Exception {
        testData = "Test data for client crypto operations".getBytes();

        // Generate test key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        testKeyPair = keyPairGenerator.generateKeyPair();
        testPublicKey = testKeyPair.getPublic();
    }

    @Test
    public void testGetClientSecurity() {
        clientCryptoFacade.getClientSecurity();
        assertNotNull(clientCryptoFacade.getClientSecurity());
    }

    @Test
    public void testCsSign_Success() {
        TpmSignRequestDto requestDto = new TpmSignRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        TpmSignResponseDto result = clientCryptoManagerService.csSign(requestDto);

        assertNotNull(result);
        assertNotNull(result.getData());
        assertFalse(result.getData().isEmpty());
    }

    @Test
    public void testCsVerify() {
        TpmSignVerifyRequestDto requestDto = new TpmSignVerifyRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setSignature(CryptoUtil.encodeToURLSafeBase64("test signature".getBytes()));
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(ClientType.LOCAL);

        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csVerify(requestDto);
        });
    }

    @Test
    public void testCsVerify_WithNullClientType() {
        TpmSignVerifyRequestDto requestDto = new TpmSignVerifyRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setSignature(CryptoUtil.encodeToURLSafeBase64("test signature".getBytes()));
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(null);

        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csVerify(requestDto);
        });
    }

    @Test
    public void testCsEncrypt_Success() {
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(ClientType.LOCAL);

        TpmCryptoResponseDto result = clientCryptoManagerService.csEncrypt(requestDto);

        assertNotNull(result);
        assertNotNull(result.getValue());
        assertFalse(result.getValue().isEmpty());

        requestDto.setClientType(ClientType.ANDROID);
        result = clientCryptoManagerService.csEncrypt(requestDto);
        assertNotNull(result);
    }

    @Test
    public void testCsEncrypt_WithNullClientType() {
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(null);

        TpmCryptoResponseDto result = clientCryptoManagerService.csEncrypt(requestDto);

        assertNotNull(result);
        assertNotNull(result.getValue());
        assertFalse(result.getValue().isEmpty());
    }

    @Test
    public void testCsDecrypt_Success() {
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        byte[] encryptedData = "encrypted data".getBytes();
        requestDto.setValue(CryptoUtil.encodeToURLSafeBase64(encryptedData));

        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csDecrypt(requestDto);
        });
    }

    @Test
    public void testGetSigningPublicKey_Success() {
        PublicKeyRequestDto requestDto = new PublicKeyRequestDto();

        PublicKeyResponseDto result = clientCryptoManagerService.getSigningPublicKey(requestDto);

        assertNotNull(result);
        assertNotNull(result.getPublicKey());
        assertFalse(result.getPublicKey().isEmpty());
    }

    @Test
    public void testGetEncPublicKey_Success() {
        PublicKeyRequestDto requestDto = new PublicKeyRequestDto();

        PublicKeyResponseDto result = clientCryptoManagerService.getEncPublicKey(requestDto);

        assertNotNull(result);
        assertNotNull(result.getPublicKey());
        assertFalse(result.getPublicKey().isEmpty());
    }

    @Test
    public void testCsSign_WithNullRequest() {
        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csSign(null);
        });
    }

    @Test
    public void testCsVerify_WithNullRequest() {
        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csVerify(null);
        });
    }

    @Test
    public void testCsEncrypt_WithNullRequest() {
        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csEncrypt(null);
        });
    }

    @Test
    public void testCsDecrypt_WithNullRequest() {
        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csDecrypt(null);
        });
    }

    @Test
    public void testGetSigningPublicKey_WithNullRequest() {
        assertDoesNotThrow(() -> {
            clientCryptoManagerService.getSigningPublicKey(null);
        });
    }

    @Test
    public void testGetEncPublicKey_WithNullRequest() {
        assertDoesNotThrow(() -> {
            clientCryptoManagerService.getEncPublicKey(null);
        });
    }

    @Test
    public void testCSVerify_Failure() {
        TpmSignRequestDto requestDto = new TpmSignRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        TpmSignResponseDto result = clientCryptoManagerService.csSign(requestDto);

        TpmSignVerifyRequestDto verifyRequestDto = new TpmSignVerifyRequestDto();
        verifyRequestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        verifyRequestDto.setSignature(result.getData());
        verifyRequestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        verifyRequestDto.setClientType(ClientType.LOCAL);
        TpmSignVerifyResponseDto verifyResult = clientCryptoManagerService.csVerify(verifyRequestDto);
        assertFalse(verifyResult.isVerified());

        verifyRequestDto.setClientType(ClientType.ANDROID);
        verifyResult = clientCryptoManagerService.csVerify(verifyRequestDto);
        assertFalse(verifyResult.isVerified());
    }

    @Test
    public void testEncrypt() {
        byte[] result = clientCryptoFacade.encrypt(testPublicKey.getEncoded(), testData);
        assertNotNull(result);
    }

    @Test
    public void testSetIsTPMRequired_DoesNothing() {
        assertDoesNotThrow(() -> {
            ClientCryptoFacade.setIsTPMRequired(true);
            ClientCryptoFacade.setIsTPMRequired(false);
        });
    }

    @Test
    public void testCsSign_WithEmptyData() {
        TpmSignRequestDto requestDto = new TpmSignRequestDto();
        requestDto.setData("");

        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csSign(requestDto);
        });
    }

    @Test
    public void testCsEncrypt_WithInvalidPublicKey() {
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setPublicKey("invalid-key");
        requestDto.setClientType(ClientType.LOCAL);

        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csEncrypt(requestDto);
        });
    }

    @Test
    public void testCsVerify_WithInvalidSignature() {
        TpmSignVerifyRequestDto requestDto = new TpmSignVerifyRequestDto();
        requestDto.setData(CryptoUtil.encodeToURLSafeBase64(testData));
        requestDto.setSignature("invalid-signature");
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(ClientType.LOCAL);

        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csVerify(requestDto);
        });
    }

    @Test
    public void testEncrypt_WithNullPublicKey() {
        assertThrows(Exception.class, () -> {
            clientCryptoFacade.encrypt(null, testData);
        });
    }

    @Test
    public void testEncrypt_WithNullData() {
        assertThrows(Exception.class, () -> {
            clientCryptoFacade.encrypt(testPublicKey.getEncoded(), null);
        });
    }

    @Test
    public void testCsEncrypt_WithEmptyValue() {
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue("");
        requestDto.setPublicKey(CryptoUtil.encodeToURLSafeBase64(testPublicKey.getEncoded()));
        requestDto.setClientType(ClientType.LOCAL);

        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csEncrypt(requestDto);
        });
    }

    @Test
    public void testCsDecrypt_WithEmptyValue() {
        TpmCryptoRequestDto requestDto = new TpmCryptoRequestDto();
        requestDto.setValue("");

        assertThrows(Exception.class, () -> {
            clientCryptoManagerService.csDecrypt(requestDto);
        });
    }

    @Test
    public void testDecrypt_CatchBlockBackwardCompatibility() {
        byte[] minimalData = new byte[300];

        for (int i = 0; i < minimalData.length; i++) {
            minimalData[i] = (byte) (i % 256);
        }

        assertThrows(Exception.class, () -> {
            clientCryptoFacade.decrypt(minimalData);
        });
    }

    @Test(expected = ClientCryptoException.class)
    public void testValidateSignature_AndroidException()  {
        clientCryptoFacade.validateSignature(ClientType.ANDROID, testPublicKey.getEncoded(), "signature".getBytes(), "test data".getBytes());
    }

    @Test(expected = ClientCryptoException.class)
    public void testEncryptAndroidException()  {
        clientCryptoFacade.encrypt(ClientType.ANDROID, "public key".getBytes(), testData);
    }
}