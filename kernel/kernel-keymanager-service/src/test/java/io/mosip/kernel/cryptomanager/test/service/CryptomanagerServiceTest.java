package io.mosip.kernel.cryptomanager.test.service;

import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.cryptomanager.constant.CryptomanagerErrorCode;
import io.mosip.kernel.cryptomanager.dto.*;
import io.mosip.kernel.cryptomanager.exception.CryptoManagerSerivceException;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
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
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;

import java.time.LocalDateTime;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(classes = {KeymanagerTestBootApplication.class})
@RunWith(SpringRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class CryptomanagerServiceTest {

    @Autowired
    private CryptomanagerService cryptomanagerService;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    private String testData = "dGVzdCBjYXNlIGRhdGEgZm9yIGNyeXB0b21hbmFnZXI";
    private String testPin = "123456";
    private String timestampStr;

    @Before
    public void setUp() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        timestampStr = DateUtils.getUTCCurrentDateTime().toString();
    }

    @After
    public void tearDown() {
        keyStoreRepository.deleteAll();
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testEncrypt_Success() {
        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("encrypt");
        requestDto.setData(testData);
        Assert.assertNotNull(requestDto.toString());

        CryptomanagerResponseDto response = cryptomanagerService.encrypt(requestDto);

        Assert.assertNotNull(response);
        Assert.assertNotEquals(testData, response.getData());

        requestDto.setSalt("IWdCK2J3S2xQTD1S");
        requestDto.setAad("dzhENWsyczlMcVpwN240WA");
        response = cryptomanagerService.encrypt(requestDto);
        Assert.assertNotNull(response);
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testEncryptCryptoManagerException() {
        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("");
        requestDto.setData(testData);
        cryptomanagerService.encrypt(requestDto);

        requestDto.setApplicationId("KERNEL");
        requestDto.setReferenceId("SIGN");
        cryptomanagerService.encrypt(requestDto);
    }

    @Test
    public void testDecrypt_Success() {
        CryptomanagerRequestDto encryptRequestDto = new CryptomanagerRequestDto();
        encryptRequestDto.setApplicationId("TEST");
        encryptRequestDto.setReferenceId("ref");
        encryptRequestDto.setData(testData);
        CryptomanagerResponseDto encryptResponse = cryptomanagerService.encrypt(encryptRequestDto);

        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("ref");
        requestDto.setData(encryptResponse.getData());

        CryptomanagerResponseDto response = cryptomanagerService.decrypt(requestDto);
        Assert.assertEquals(response.getData(), testData);

        encryptRequestDto.setSalt("IWdCK2J3S2xQTD1S");
        encryptRequestDto.setAad("dzhENWsyczlMcVpwN240WA");
        encryptResponse = cryptomanagerService.encrypt(encryptRequestDto);

        requestDto.setSalt("IWdCK2J3S2xQTD1S");
        requestDto.setAad("dzhENWsyczlMcVpwN240WA");
        requestDto.setData(encryptResponse.getData());
        response = cryptomanagerService.decrypt(requestDto);
        Assert.assertEquals(response.getData(), testData);
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testDecryptCryptoManagerException() {
        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("INVALID_APP_ID");
        cryptomanagerService.decrypt(requestDto);
    }

    @Test
    public void testEncryptWithPin_Success() {
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setData(testData);
        requestDto.setUserPin(testPin);

        CryptoWithPinResponseDto response = cryptomanagerService.encryptWithPin(requestDto);

        Assert.assertNotNull(response);
        Assert.assertNotEquals(testData, response.getData());
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testEncryptWithPinCryptoManagerException() {
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setData("");
        cryptomanagerService.encryptWithPin(requestDto);
    }

    @Test
    public void testDecryptWithPin_Success() {
        CryptoWithPinRequestDto encryptRequest = new CryptoWithPinRequestDto();
        encryptRequest.setData(testData);
        encryptRequest.setUserPin(testPin);
        CryptoWithPinResponseDto encryptResponse = cryptomanagerService.encryptWithPin(encryptRequest);

        CryptoWithPinRequestDto decryptRequest = new CryptoWithPinRequestDto();
        decryptRequest.setData(encryptResponse.getData());
        decryptRequest.setUserPin(testPin);

        CryptoWithPinResponseDto response = cryptomanagerService.decryptWithPin(decryptRequest);

        Assert.assertEquals(testData, response.getData());
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testDecryptWithPinCryptoManagerException() {
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setUserPin("");
        cryptomanagerService.decryptWithPin(requestDto);
    }

    @Test
    public void testJwtEncrypt_Success() {
        JWTEncryptRequestDto requestDto = new JWTEncryptRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("json");
        requestDto.setData("eyAiZGF0YSI6ICJ0ZXN0IGRhdGEgZm9yIGNyeXB0b21hbmFnZXIiIH0");
        Assert.assertNotNull(requestDto.toString());

        JWTCipherResponseDto response = cryptomanagerService.jwtEncrypt(requestDto);
        Assert.assertNotNull(response);

        requestDto.setEnableDefCompression(true);
        requestDto.setIncludeCertificate(true);
        requestDto.setIncludeCertHash(true);
        requestDto.setJwkSetUrl("https://test.mosip.io/jwks");
        response = cryptomanagerService.jwtEncrypt(requestDto);

        Assert.assertNotNull(response);
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testJwtEncryptCryptoManagerException() {
        JWTEncryptRequestDto requestDto = new JWTEncryptRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("jwt");
        requestDto.setData("Tm9uIEpzb24gRGF0YQ");
        cryptomanagerService.jwtEncrypt(requestDto);
    }

    @Test
    public void testJwtDecrypt_Success() {
        JWTEncryptRequestDto encryptRequestDto = new JWTEncryptRequestDto();
        encryptRequestDto.setApplicationId("TEST");
        encryptRequestDto.setReferenceId("decrypt");
        encryptRequestDto.setData("eyAiZGF0YSI6ICJ0ZXN0IGRhdGEgZm9yIGNyeXB0b21hbmFnZXIiIH0");
        JWTCipherResponseDto encryptResponse = cryptomanagerService.jwtEncrypt(encryptRequestDto);

        JWTDecryptRequestDto requestDto = new JWTDecryptRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("decrypt");
        requestDto.setEncData(encryptResponse.getData());
        Assert.assertNotNull(requestDto.toString());

        JWTCipherResponseDto response = cryptomanagerService.jwtDecrypt(requestDto);

        Assert.assertEquals("eyAiZGF0YSI6ICJ0ZXN0IGRhdGEgZm9yIGNyeXB0b21hbmFnZXIiIH0", response.getData());

        encryptRequestDto.setEnableDefCompression(true);
        encryptRequestDto.setIncludeCertificate(true);
        encryptRequestDto.setIncludeCertHash(true);
        encryptRequestDto.setJwkSetUrl("https://test.mosip.io/jwks");
        encryptResponse = cryptomanagerService.jwtEncrypt(encryptRequestDto);

        requestDto.setEncData(encryptResponse.getData());
        response = cryptomanagerService.jwtDecrypt(requestDto);
        Assert.assertEquals("eyAiZGF0YSI6ICJ0ZXN0IGRhdGEgZm9yIGNyeXB0b21hbmFnZXIiIH0", response.getData());
    }

    @Test
    public void testJwtDecryptCryptoManagerException() {
        JWTDecryptRequestDto requestDto = new JWTDecryptRequestDto();
        requestDto.setApplicationId("TEST");
        requestDto.setReferenceId("jwt");
        requestDto.setEncData("");
        CryptoManagerSerivceException exception = assertThrows(CryptoManagerSerivceException.class, () -> {
            cryptomanagerService.jwtDecrypt(requestDto);
        });
        Assert.assertEquals(CryptomanagerErrorCode.INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        Assert.assertEquals("data should not be null or empty", exception.getErrorText());

        requestDto.setEncData("bchdsc87y3298hduwqhqois*@!#&Y@#^!sjwioiwqwspsdcb");
        exception = assertThrows(CryptoManagerSerivceException.class, () -> {
            cryptomanagerService.jwtDecrypt(requestDto);
        });
        Assert.assertEquals(CryptomanagerErrorCode.JWE_DECRYPTION_INTERNAL_ERROR.getErrorCode(), exception.getErrorCode());
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testGenerateArgon2Hash_Success() {
        Argon2GenerateHashRequestDto requestDto = new Argon2GenerateHashRequestDto();
        Argon2GenerateHashResponseDto response = cryptomanagerService.generateArgon2Hash(requestDto);
    }

    @Test
    public void testEncrypt_InvalidApplicationId() {
        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("INVALID_APP");
        requestDto.setReferenceId("");
        requestDto.setTimeStamp(LocalDateTime.parse(timestampStr));
        requestDto.setData(testData);

        CryptoManagerSerivceException exception = assertThrows(CryptoManagerSerivceException.class, () -> {
            cryptomanagerService.encrypt(requestDto);
        });

        Assert.assertNotNull(exception);
    }

    @Test
    public void testEncryptWithPin_InvalidPin() {
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setData(testData);
        requestDto.setUserPin(""); // Empty PIN

        CryptoManagerSerivceException exception = assertThrows(CryptoManagerSerivceException.class, () -> {
            cryptomanagerService.encryptWithPin(requestDto);
        });

        Assert.assertNotNull(exception);
    }

    @Test
    public void testDecryptWithPin_WrongPin() {
        CryptoWithPinRequestDto encryptRequest = new CryptoWithPinRequestDto();
        encryptRequest.setData(testData);
        encryptRequest.setUserPin(testPin);

        CryptoWithPinResponseDto encryptResponse = cryptomanagerService.encryptWithPin(encryptRequest);

        CryptoWithPinRequestDto decryptRequest = new CryptoWithPinRequestDto();
        decryptRequest.setData(encryptResponse.getData());
        decryptRequest.setUserPin("wrong-pin");

        InvalidDataException exception = assertThrows(InvalidDataException.class, () -> {
            cryptomanagerService.decryptWithPin(decryptRequest);
        });

        Assert.assertNotNull(exception);
    }

    @Test
    public void testJwtEncrypt_InvalidApplicationId() {
        JWTEncryptRequestDto requestDto = new JWTEncryptRequestDto();
        requestDto.setApplicationId("INVALID_APP");
        requestDto.setReferenceId("");
        CryptoManagerSerivceException exception = assertThrows(CryptoManagerSerivceException.class, () -> {
            cryptomanagerService.jwtEncrypt(requestDto);
        });

        Assert.assertNotNull(exception);
    }

    @Test
    public void testJwtDecrypt_InvalidData() {
        JWTDecryptRequestDto requestDto = new JWTDecryptRequestDto();
        requestDto.setApplicationId("REGISTRATION");
        requestDto.setReferenceId("");

        CryptoManagerSerivceException exception = assertThrows(CryptoManagerSerivceException.class, () -> {
            cryptomanagerService.jwtDecrypt(requestDto);
        });

        Assert.assertNotNull(exception);
    }

    @Test
    public void testGenerateArgon2Hash_NullInput() {
        Argon2GenerateHashRequestDto requestDto = new Argon2GenerateHashRequestDto();
        requestDto.setInputData(null);

        CryptoManagerSerivceException exception = assertThrows(CryptoManagerSerivceException.class, () -> {
            cryptomanagerService.generateArgon2Hash(requestDto);
        });

        Assert.assertNotNull(exception);
    }

    @Test(expected = CryptoManagerSerivceException.class)
    public void testEncrypt_WithReferenceId() {
        CryptomanagerRequestDto requestDto = new CryptomanagerRequestDto();
        requestDto.setApplicationId("KERNEL");
        requestDto.setReferenceId("SIGN");
        requestDto.setTimeStamp(LocalDateTime.parse(timestampStr));
        requestDto.setData(testData);

        cryptomanagerService.encrypt(requestDto);
    }
}
