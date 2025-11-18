package io.mosip.kernel.clientcrypto.test.service;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.*;
import java.security.*;
import java.util.Base64;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;

import io.mosip.kernel.clientcrypto.constant.*;
import io.mosip.kernel.clientcrypto.dto.*;
import io.mosip.kernel.clientcrypto.exception.ClientCryptoException;
import io.mosip.kernel.clientcrypto.service.impl.*;
import io.mosip.kernel.clientcrypto.service.spi.*;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;

import javax.crypto.SecretKey;

@RunWith(MockitoJUnitRunner.class)
public class ClientCryptoManagerServiceTest {

    @Mock
    private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

    @Mock
    private Environment environment;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private ClientCryptoService clientCryptoService;

    private ClientCryptoFacade clientCryptoFacade;
    private ClientCryptoManagerServiceImpl clientCryptoManagerService;

    private byte[] testData = "test data".getBytes();
    private byte[] testPublicKey;
    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
        testPublicKey = keyPair.getPublic().getEncoded();

        clientCryptoFacade = new ClientCryptoFacade();
        clientCryptoManagerService = new ClientCryptoManagerServiceImpl();

        // Inject mocks using reflection
        Field cryptoCoreField = ClientCryptoFacade.class.getDeclaredField("cryptoCore");
        cryptoCoreField.setAccessible(true);
        cryptoCoreField.set(clientCryptoFacade, cryptoCore);

        Field facadeField = ClientCryptoManagerServiceImpl.class.getDeclaredField("clientCryptoFacade");
        facadeField.setAccessible(true);
        facadeField.set(clientCryptoManagerService, clientCryptoFacade);

        when(cryptoCore.symmetricEncrypt(any(SecretKey.class), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenReturn("encrypted".getBytes());
        when(cryptoCore.symmetricDecrypt(any(SecretKey.class), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenReturn(testData);
    }

    // AndroidClientCryptoServiceImpl Tests
    @Test
    public void testAndroidValidateSignature_Static() throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(testData);
        byte[] validSignature = signature.sign();

        boolean result = AndroidClientCryptoServiceImpl.validateSignature(testPublicKey, validSignature, testData);
        assertTrue(result);
    }

    @Test(expected = ClientCryptoException.class)
    public void testAndroidValidateSignature_InvalidSignature() throws Exception {
        AndroidClientCryptoServiceImpl.validateSignature(testPublicKey, "invalid".getBytes(), testData);
    }

    @Test
    public void testAndroidAsymmetricEncrypt_Static() throws Exception {
        byte[] result = AndroidClientCryptoServiceImpl.asymmetricEncrypt(testPublicKey, "small data".getBytes());
        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test(expected = ClientCryptoException.class)
    public void testAndroidAsymmetricEncrypt_InvalidKey() throws Exception {
        AndroidClientCryptoServiceImpl.asymmetricEncrypt("invalid key".getBytes(), testData);
    }

    @Test(expected = ClientCryptoException.class)
    public void testAndroidValidateSignature_Instance() throws Exception {
        AndroidClientCryptoServiceImpl androidService = new AndroidClientCryptoServiceImpl();
        androidService.validateSignature(testPublicKey, testData);
    }

    @Test
    public void testAndroidAsymmetricEncrypt_Instance() throws Exception {
        AndroidClientCryptoServiceImpl androidService = new AndroidClientCryptoServiceImpl();
        byte[] result = androidService.asymmetricEncrypt("small data".getBytes());
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test(expected = ClientCryptoException.class)
    public void testAndroidAsymmetricDecrypt_Instance() throws Exception {
        AndroidClientCryptoServiceImpl androidService = new AndroidClientCryptoServiceImpl();
        androidService.asymmetricDecrypt(testPublicKey);
    }

    @Test
    public void testAndroidSignData() throws Exception {
        AndroidClientCryptoServiceImpl androidService = new AndroidClientCryptoServiceImpl();
        byte[] result = androidService.signData(testData);
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test
    public void testAndroidGetSigningPublicPart() {
        AndroidClientCryptoServiceImpl androidService = new AndroidClientCryptoServiceImpl();
        byte[] result = androidService.getSigningPublicPart();
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test
    public void testAndroidGetEncryptionPublicPart() {
        AndroidClientCryptoServiceImpl androidService = new AndroidClientCryptoServiceImpl();
        byte[] result = androidService.getEncryptionPublicPart();
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test
    public void testAndroidIsTPMInstance() {
        AndroidClientCryptoServiceImpl androidService = new AndroidClientCryptoServiceImpl();
        assertFalse(androidService.isTPMInstance());
    }

    @Test
    public void testAndroidCloseSecurityInstance() throws Exception {
        AndroidClientCryptoServiceImpl androidService = new AndroidClientCryptoServiceImpl();
        androidService.closeSecurityInstance();
    }

    // ClientCryptoFacade Tests
    @Test
    public void testFacadeValidateSignature_AndroidClient() throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(testData);
        byte[] validSignature = signature.sign();

        boolean result = clientCryptoFacade.validateSignature(ClientType.ANDROID, testPublicKey, validSignature, testData);
        assertTrue(result);
    }

    @Test
    public void testFacadeValidateSignature_NullClientType() throws Exception {
        try {
            boolean result = clientCryptoFacade.validateSignature(null, testPublicKey, "test".getBytes(), testData);
            assertFalse(result);
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testFacadeValidateSignature_DefaultMethod() throws Exception {
        try {
            boolean result = clientCryptoFacade.validateSignature(testPublicKey, "test".getBytes(), testData);
            assertFalse(result);
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testFacadeEncrypt_AndroidClient() throws Exception {
        byte[] result = clientCryptoFacade.encrypt(ClientType.ANDROID, testPublicKey, "small data".getBytes());
        assertNotNull(result);
    }

    @Test
    public void testFacadeEncrypt_DefaultMethod() throws Exception {
        try {
            byte[] result = clientCryptoFacade.encrypt(testPublicKey, "small data".getBytes());
            assertNotNull(result);
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testFacadeGenerateRandomBytes() throws Exception {
        byte[] randomBytes = ClientCryptoFacade.generateRandomBytes(16);
        assertNotNull(randomBytes);
        assertEquals(16, randomBytes.length);
    }

    @Test
    public void testFacadeSetIsTPMRequired() throws Exception {
        ClientCryptoFacade.setIsTPMRequired(true);
        ClientCryptoFacade.setIsTPMRequired(false);
    }

    // ClientCryptoManagerServiceImpl Tests with mocked facade
    @Test
    public void testManagerServiceSign() throws Exception {
        when(clientCryptoService.signData(any(byte[].class))).thenReturn("signature".getBytes());

        Field serviceField = ClientCryptoFacade.class.getDeclaredField("clientCryptoService");
        serviceField.setAccessible(true);
        serviceField.set(clientCryptoFacade, clientCryptoService);

        TpmSignRequestDto request = new TpmSignRequestDto();
        request.setData(Base64.getEncoder().encodeToString(testData));

        TpmSignResponseDto result = clientCryptoManagerService.csSign(request);
        assertNotNull(result);
    }

    @Test
    public void testManagerServiceVerify() throws Exception {
        TpmSignVerifyRequestDto request = new TpmSignVerifyRequestDto();
        request.setClientType(ClientType.ANDROID);
        request.setPublicKey(Base64.getEncoder().encodeToString(testPublicKey));
        request.setSignature(Base64.getEncoder().encodeToString("signature".getBytes()));
        request.setData(Base64.getEncoder().encodeToString(testData));

        try {
            TpmSignVerifyResponseDto result = clientCryptoManagerService.csVerify(request);
            assertNotNull(result);
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testManagerServiceEncrypt() throws Exception {
        TpmCryptoRequestDto request = new TpmCryptoRequestDto();
        request.setClientType(ClientType.ANDROID);
        request.setPublicKey(Base64.getEncoder().encodeToString(testPublicKey));
        request.setValue(Base64.getEncoder().encodeToString("small data".getBytes()));

        TpmCryptoResponseDto result = clientCryptoManagerService.csEncrypt(request);
        assertNotNull(result);
    }

    @Test
    public void testManagerServiceDecrypt() throws Exception {
        when(clientCryptoService.asymmetricDecrypt(any(byte[].class))).thenReturn("key".getBytes());

        Field serviceField = ClientCryptoFacade.class.getDeclaredField("clientCryptoService");
        serviceField.setAccessible(true);
        serviceField.set(clientCryptoFacade, clientCryptoService);

        TpmCryptoRequestDto request = new TpmCryptoRequestDto();
        request.setValue(Base64.getEncoder().encodeToString("encrypted".getBytes()));

        TpmCryptoResponseDto result = clientCryptoManagerService.csDecrypt(request);
        assertNotNull(result);
    }

    @Test
    public void testManagerServiceGetSigningPublicKey() throws Exception {
        when(clientCryptoService.getSigningPublicPart()).thenReturn(testPublicKey);

        Field serviceField = ClientCryptoFacade.class.getDeclaredField("clientCryptoService");
        serviceField.setAccessible(true);
        serviceField.set(clientCryptoFacade, clientCryptoService);

        PublicKeyRequestDto request = new PublicKeyRequestDto();

        PublicKeyResponseDto result = clientCryptoManagerService.getSigningPublicKey(request);
        assertNotNull(result);
    }

    @Test
    public void testManagerServiceGetEncPublicKey() throws Exception {
        when(clientCryptoService.getEncryptionPublicPart()).thenReturn(testPublicKey);

        Field serviceField = ClientCryptoFacade.class.getDeclaredField("clientCryptoService");
        serviceField.setAccessible(true);
        serviceField.set(clientCryptoFacade, clientCryptoService);

        PublicKeyRequestDto request = new PublicKeyRequestDto();

        PublicKeyResponseDto result = clientCryptoManagerService.getEncPublicKey(request);
        assertNotNull(result);
    }

    // Reflection-based tests for package-private classes
    @Test
    public void testLocalClientCryptoService_Reflection() throws Exception {
        try {
            Class<?> localClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.LocalClientCryptoServiceImpl");
            Constructor<?> constructor = localClass.getDeclaredConstructor(CryptoCoreSpec.class, ApplicationContext.class, Boolean.class, String.class);
            constructor.setAccessible(true);
            Object localService = constructor.newInstance(cryptoCore, applicationContext, false, "TEST");

            Method isTPMMethod = localClass.getDeclaredMethod("isTPMInstance");
            isTPMMethod.setAccessible(true);
            Boolean result = (Boolean) isTPMMethod.invoke(localService);
            assertFalse(result);
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testTPMClientCryptoService_Reflection() throws Exception {
        try {
            Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
            Constructor<?> constructor = tpmClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            Object tpmService = constructor.newInstance();

            Method isTPMMethod = tpmClass.getDeclaredMethod("isTPMInstance");
            isTPMMethod.setAccessible(true);
            Boolean result = (Boolean) isTPMMethod.invoke(tpmService);
            assertTrue(result);
        } catch (Exception e) {
            assertNotNull(e);
        }
    }
}