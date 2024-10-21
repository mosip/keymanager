
package io.mosip.kernel.cryptomanager.test.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.cryptomanager.dto.*;
import io.mosip.kernel.cryptomanager.service.impl.CryptomanagerServiceImpl;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keygenerator.bouncycastle.KeyGenerator;
import io.mosip.kernel.keymanager.hsm.impl.KeyStoreImpl;
import io.mosip.kernel.keymanagerservice.helper.PrivateKeyDecryptorHelper;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import org.jose4j.jwe.JsonWebEncryption;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import javax.crypto.SecretKey;
import java.security.*;
import java.security.cert.Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = KeymanagerTestBootApplication.class)
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
public class CryptomanagerServiceTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockBean
    KeyGenerator keyGenerator;

    @MockBean
    CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

    @MockBean
    CryptomanagerUtils cryptomanagerUtil;

    @MockBean
    PrivateKeyDecryptorHelper privateKeyDecryptorHelper;

    @MockBean
    KeymanagerUtil keymanagerUtil;

    @MockBean
    KeymanagerService keymanagerService;

    @MockBean
    KeyStoreImpl keyStore;

    @MockBean
    CryptomanagerServiceImpl cryptomanagerServiceImpl;

    @MockBean
    JsonWebEncryption jsonWebEncryption;

    @MockBean
    CryptoUtil cryptoUtil;

    private SecretKey secretKey;

    private PublicKey publicKey;

    private CryptomanagerRequestDto requestDto;

    private  RequestWrapper<CryptomanagerRequestDto> reqWrapperDto;

    private Certificate certificate;

    @Before
    public void setUp() {
        secretKey = mock(SecretKey.class);
        publicKey = mock(PublicKey.class);
        certificate = mock(Certificate.class);
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


        requestDto = new CryptomanagerRequestDto();
        requestDto.setData("Example");
        requestDto.setApplicationId("APPID");
        requestDto.setReferenceId("REFID");
        requestDto.setTimeStamp(LocalDateTime.now(ZoneId.of("UTC")));

        reqWrapperDto = new RequestWrapper<>();
        reqWrapperDto.setId("ID");
        reqWrapperDto.setMetadata(null);
        reqWrapperDto.setRequest(requestDto);
        reqWrapperDto.setRequesttime(LocalDateTime.now());
        reqWrapperDto.setVersion("v1.0");
    }

    /**
     * TEST SCENARIO : Testing CryptomanagerService
     *
     * @throws Exception
     */
    @Test
    @WithUserDetails("reg-processor")
    public void encryptTest() throws Exception {
        doNothing().when(cryptomanagerUtil).validateKeyIdentifierIds(requestDto.getApplicationId(), requestDto.getReferenceId());
        when(cryptomanagerUtil.isValidSalt(anyString())).thenReturn(true);
        when(cryptomanagerUtil.isValidSalt(anyString())).thenReturn(false);
        when(cryptomanagerUtil.decodeBase64Data(anyString())).thenReturn("decoded base64".getBytes());
        when(cryptoCore.symmetricEncrypt(secretKey, requestDto.getData().getBytes(), new byte[0])).thenReturn("encrypted-data".getBytes());
        when(cryptoCore.asymmetricEncrypt(publicKey, secretKey.getEncoded())).thenReturn("encrypted-symmetric-key".getBytes());
        when(cryptomanagerUtil.getCertificate(requestDto)).thenReturn(certificate);
        when(cryptomanagerUtil.getCertificateThumbprint(certificate)).thenReturn("cert-thumbprint".getBytes());
        when(cryptomanagerUtil.concatCertThumbprint(any(byte[].class), any(byte[].class))).thenReturn("finalData".getBytes());
        when(cryptomanagerUtil.concatByteArrays(any(byte[].class), any(byte[].class))).thenReturn("finalData".getBytes());

        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        responseDto.setData("CombinedEncryptedData");
        String json = objectMapper.writeValueAsString(responseDto);
        mockMvc.perform(MockMvcRequestBuilders.post("/encrypt").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void decryptTest() throws Exception {
        when(cryptomanagerUtil.hasKeyAccess(requestDto.getApplicationId())).thenReturn(true);
        when(cryptomanagerUtil.decodeBase64Data(requestDto.getData())).thenReturn("cdsidadai".getBytes());
        when(cryptomanagerUtil.getDecryptedSymmetricKey(requestDto)).thenReturn(secretKey);
        when(cryptoCore.symmetricDecrypt(eq(secretKey), any(byte[].class), any(byte[].class)))
                .thenReturn("Decrypt-Data".getBytes());
        when(cryptomanagerUtil.isValidSalt(anyString())).thenReturn(true);
        when(cryptomanagerUtil.isValidSalt(anyString())).thenReturn(false);

        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        responseDto.setData("Decrypted-Data");
        String json = objectMapper.writeValueAsString(responseDto);
        mockMvc.perform(MockMvcRequestBuilders.post("/decrypt").contentType(MediaType.APPLICATION_JSON)
                .content(json)).andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void encryptWithPinTest() throws Exception {
        CryptoWithPinRequestDto requestDto1 = new CryptoWithPinRequestDto();
        requestDto1.setData("Test data");
        requestDto1.setUserPin("1234");

        byte[] expectedEncryptedData = "encryptedData".getBytes();

        when(cryptomanagerUtil.isDataValid(anyString())).thenReturn(true);
        when(cryptomanagerUtil.isDataValid(anyString())).thenReturn(false);
        when(cryptoCore.symmetricEncrypt(eq(secretKey), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenReturn(expectedEncryptedData);

        assertNotNull(requestDto1.getUserPin());
        CryptoWithPinResponseDto responseDto = new CryptoWithPinResponseDto();
        responseDto.setData("Encrypted-Data");
        String json = objectMapper.writeValueAsString(responseDto);
        mockMvc.perform(post("/encryptWithPin").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void decryptWithPinTest() throws Exception {
        CryptoWithPinRequestDto requestDto1 = new CryptoWithPinRequestDto();
        requestDto1.setData("hdiuhdkbdihkbw==");
        requestDto1.setUserPin("1234");

        byte[] expectedDecryptedData = "decryptedData".getBytes();
        when(cryptomanagerUtil.isDataValid(anyString())).thenReturn(true);
        when(cryptomanagerUtil.decodeBase64Data(requestDto1.getData())).thenReturn("Base64 Decoded Text".getBytes());
        when(cryptoCore.symmetricDecrypt(eq(secretKey), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenReturn(expectedDecryptedData);

        assertNotNull(requestDto1.getUserPin());
        CryptoWithPinResponseDto responseDto = new CryptoWithPinResponseDto();
        responseDto.setData("Decrypted-Data");
        String json = objectMapper.writeValueAsString(responseDto);
        mockMvc.perform(post("/decryptWithPin").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void jwtEncryptTest() throws Exception {
        JWTEncryptRequestDto requestDto1 = new JWTEncryptRequestDto();
        requestDto1.setApplicationId("TESTID");
        requestDto1.setData("dveajdpsnks");
        requestDto1.setReferenceId("test123");
        requestDto1.setX509Certificate("valid-cert-data");

        when(cryptomanagerUtil.isDataValid(anyString())).thenReturn(true);
        when(cryptomanagerUtil.convertToCertificate(anyString())).thenReturn(certificate);
        doNothing().when(cryptomanagerUtil).validateKeyIdentifierIds(requestDto.getApplicationId(), requestDto.getReferenceId());
        when(cryptomanagerUtil.decodeBase64Data(anyString())).thenReturn("decoded-data".getBytes());
        doNothing().when(cryptomanagerUtil).checkForValidJsonData(anyString());
        when(cryptomanagerUtil.getCertificate(requestDto1.getApplicationId(), requestDto1.getReferenceId())).thenReturn(certificate);
        doNothing().when(cryptomanagerUtil).validateEncKeySize(certificate);
        doNothing().when(cryptomanagerUtil).validateEncryptData(anyString());
        when(cryptomanagerUtil.isIncludeAttrsValid(anyBoolean(), anyBoolean())).thenReturn(true);

        JWTCipherResponseDto responseDto = new JWTCipherResponseDto();
        responseDto.setData("jwt-Encytpion");
        responseDto.setTimestamp(LocalDateTime.now(ZoneId.of("UTC")));
        String json = objectMapper.writeValueAsString(responseDto);
        mockMvc.perform(post("/jwtEncrypt").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void jwtDecryptTest() throws Exception {
        JWTDecryptRequestDto requestDto1 = new JWTDecryptRequestDto();
        requestDto1.setApplicationId("TESTID");
        requestDto1.setEncData("anuhsbisinknskd");
        requestDto1.setReferenceId("test123");

        doNothing().when(cryptomanagerUtil).validateKeyIdentifierIds(requestDto.getApplicationId(), requestDto.getReferenceId());
        when(cryptomanagerUtil.isDataValid(anyString())).thenReturn(true);
        when(jsonWebEncryption.getKeyIdHeaderValue()).thenReturn("valid-key-id");

        JWTCipherResponseDto responseDto = new JWTCipherResponseDto();
        responseDto.setData("jwt_Decryption");
        responseDto.setTimestamp(LocalDateTime.now(ZoneId.of("UTC")));
        String json = objectMapper.writeValueAsString(responseDto);
        mockMvc.perform(post("/jwtDecrypt").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }

    @Test
    @WithUserDetails("reg-processor")
    public void generateArgon2HashTest() throws Exception {
        Argon2GenerateHashRequestDto requestDto1 = new Argon2GenerateHashRequestDto();
        requestDto1.setInputData("RXhhbXBsZQ==");
        requestDto1.setSalt("vhksjdiushiufhs");

        doNothing().when(cryptomanagerUtil).validateInputData(requestDto1.getInputData());
        when(cryptomanagerUtil.isDataValid(anyString())).thenReturn(true);

        Argon2GenerateHashResponseDto responseDto = new Argon2GenerateHashResponseDto();
        responseDto.setHashValue("uhscdsciudewdbi==");
        responseDto.setSalt("vhsdoicscdskjs");
        String json = objectMapper.writeValueAsString(responseDto);
        mockMvc.perform(post("/generateArgon2Hash").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk());
    }
}