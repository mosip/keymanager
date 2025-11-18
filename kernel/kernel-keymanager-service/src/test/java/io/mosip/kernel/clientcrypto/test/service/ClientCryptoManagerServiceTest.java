package io.mosip.kernel.clientcrypto.test.service;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Comparator;

import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import io.mosip.kernel.clientcrypto.constant.ClientCryptoErrorConstants;
import io.mosip.kernel.clientcrypto.constant.ClientCryptoManagerConstant;
import io.mosip.kernel.clientcrypto.constant.ClientType;
import io.mosip.kernel.clientcrypto.exception.ClientCryptoException;
import io.mosip.kernel.clientcrypto.service.impl.AndroidClientCryptoServiceImpl;
import io.mosip.kernel.clientcrypto.service.impl.ClientCryptoFacade;
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoService;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;
import tss.Tpm;
import tss.TpmDeviceBase;
import tss.TpmDeviceTbs;
import tss.tpm.CreatePrimaryResponse;
import tss.tpm.TPMT_PUBLIC;
import tss.tpm.TPMA_OBJECT;
import tss.tpm.TPMS_NULL_ASYM_SCHEME;
import tss.tpm.TPMS_NULL_SIG_SCHEME;
import tss.tpm.TPMS_SIGNATURE_RSASSA;
import tss.tpm.TPMT_TK_HASHCHECK;
import tss.tpm.TPMS_RSA_PARMS;
import tss.tpm.TPMT_SYM_DEF_OBJECT;
import tss.tpm.TPMS_SIG_SCHEME_RSASSA;
import tss.tpm.TPMS_ENC_SCHEME_OAEP;
import tss.tpm.TPMS_SENSITIVE_CREATE;
import tss.tpm.TPMS_PCR_SELECTION;
import tss.tpm.TPM2B_PUBLIC_KEY_RSA;
import tss.tpm.TPM_HANDLE;
import tss.tpm.TPM_RH;
import tss.tpm.TPM_ALG_ID;

@RunWith(MockitoJUnitRunner.class)
public class ClientCryptoManagerServiceTest {

    @Mock
    private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

    @Mock
    private ClientCryptoService clientCryptoService;

    @Mock
    private org.springframework.context.ApplicationContext applicationContext;

    private KeyPair keyPair;
    private byte[] sampleData;
    private ClientCryptoFacade clientCryptoFacade;
    private static final int symmetricKeyLength = 32;
    private static final int ivLength = 12;
    private static final int aadLength = 16;

    @Before
    public void setUp() throws Exception {
        keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        sampleData = "client-data".getBytes(StandardCharsets.UTF_8);

        clientCryptoFacade = new ClientCryptoFacade();
        injectField(clientCryptoFacade, "cryptoCore", cryptoCore);
        injectField(clientCryptoFacade, "applicationContext", applicationContext);
        injectField(clientCryptoFacade, "useResidentServiceModuleKey", false);
        injectField(clientCryptoFacade, "residentServiceAppId", "RESIDENT");
        injectField(clientCryptoFacade, "ivLength", 12);
        injectField(clientCryptoFacade, "aadLength", 16);
        injectField(clientCryptoFacade, "symmetricKeyLength", 32);

        setStaticField(ClientCryptoFacade.class, "clientCryptoService", clientCryptoService);
        setStaticField(ClientCryptoFacade.class, "secureRandom", new java.security.SecureRandom());
        setStaticField(Class.forName("io.mosip.kernel.clientcrypto.service.impl.LocalClientCryptoServiceImpl"),
                "cryptoCore", cryptoCore);

        lenient().when(cryptoCore.symmetricEncrypt(any(SecretKey.class), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenReturn("cipher".getBytes(StandardCharsets.UTF_8));
        lenient().when(cryptoCore.symmetricDecrypt(any(SecretKey.class), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenReturn(sampleData);
        lenient().when(cryptoCore.asymmetricEncrypt(any(PublicKey.class), any(byte[].class)))
                .thenAnswer(inv -> ((byte[]) inv.getArgument(1)));
        lenient().when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(byte[].class)))
                .thenAnswer(inv -> ((byte[]) inv.getArgument(1)));
    }

    @After
    public void tearDown() throws Exception {
        setStaticField(ClientCryptoFacade.class, "clientCryptoService", null);
        setStaticField(ClientCryptoFacade.class, "secureRandom", null);
        setStaticField(Class.forName("io.mosip.kernel.clientcrypto.service.impl.LocalClientCryptoServiceImpl"),
                "cryptoCore", null);
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        resetTpmStatics(tpmClass);
        cleanKeysDirectory();
    }

    @Test
    public void testAndroidValidateSignatureSuccess() throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(sampleData);
        byte[] signed = signature.sign();

        boolean verified = AndroidClientCryptoServiceImpl.validateSignature(keyPair.getPublic().getEncoded(),
                signed, sampleData);

        assertTrue(verified);
    }

    @Test(expected = ClientCryptoException.class)
    public void testAndroidValidateSignatureThrowsException() throws Exception {
        AndroidClientCryptoServiceImpl.validateSignature("invalid".getBytes(StandardCharsets.UTF_8),
                "sig".getBytes(StandardCharsets.UTF_8), sampleData);
    }

    @Test
    public void testAndroidAsymmetricEncryptProducesCiphertext() throws Exception {
        byte[] cipher = AndroidClientCryptoServiceImpl.asymmetricEncrypt(keyPair.getPublic().getEncoded(), sampleData);
        assertNotNull(cipher);
        assertTrue(cipher.length > 0);
    }

    @Test
    public void testClientCryptoFacadeEncryptWithAndroidClient() {
        byte[] envelope = clientCryptoFacade.encrypt(ClientType.ANDROID,
                keyPair.getPublic().getEncoded(), sampleData);

        assertNotNull(envelope);
        assertTrue(envelope.length > 0);
        verify(cryptoCore).symmetricEncrypt(any(SecretKey.class), eq(sampleData),
                any(byte[].class), any(byte[].class));
    }

    @Test
    public void testClientCryptoFacadeDecryptUsesClientSecurity() throws Exception {
        byte[] secret = new byte[32];
        byte[] iv = new byte[12];
        byte[] aad = new byte[16];
        byte[] cipher = "cipher".getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[secret.length + iv.length + aad.length + cipher.length];

        System.arraycopy(new byte[secret.length], 0, payload, 0, secret.length);
        System.arraycopy(iv, 0, payload, secret.length, iv.length);
        System.arraycopy(aad, 0, payload, secret.length + iv.length, aad.length);
        System.arraycopy(cipher, 0, payload, secret.length + iv.length + aad.length, cipher.length);

        when(clientCryptoService.asymmetricDecrypt(any(byte[].class))).thenReturn(secret);

        byte[] result = clientCryptoFacade.decrypt(payload);

        assertArrayEquals(sampleData, result);
        verify(clientCryptoService).asymmetricDecrypt(any(byte[].class));
        verify(cryptoCore).symmetricDecrypt(any(SecretKey.class), any(byte[].class), any(byte[].class), any(byte[].class));
    }

    @Test
    public void testClientCryptoFacadeGenerateRandomBytes() {
        byte[] random = ClientCryptoFacade.generateRandomBytes(24);
        assertNotNull(random);
        assertEquals(24, random.length);
    }

    @Test
    public void testLocalClientCryptoServiceSignAndValidate() throws Exception {
        ClientCryptoService localService = createLocalClientCryptoService();
        byte[] signature = localService.signData(sampleData);
        assertNotNull(signature);
        assertTrue(localService.validateSignature(signature, sampleData));
    }

    @Test
    public void testLocalClientCryptoServiceAsymmetricEncryptUsesCryptoCore() throws Exception {
        ClientCryptoService localService = createLocalClientCryptoService();
        byte[] result = localService.asymmetricEncrypt(sampleData);
        assertArrayEquals(sampleData, result);
        verify(cryptoCore).asymmetricEncrypt(any(PublicKey.class), eq(sampleData));
    }

    @Test
    public void testLocalClientCryptoServiceGenerateRandomBytes() throws Exception {
        Class<?> localClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.LocalClientCryptoServiceImpl");
        Method method = localClass.getDeclaredMethod("generateRandomBytes", int.class);
        method.setAccessible(true);
        byte[] random = (byte[]) method.invoke(null, 8);
        assertEquals(8, random.length);
    }

    @Test
    public void testTpmClientCryptoServiceOperations() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Tpm tpmMock = mock(Tpm.class);

        TPMT_PUBLIC signingPublic = Mockito.mock(TPMT_PUBLIC.class);
        TPMT_PUBLIC encryptionPublic = Mockito.mock(TPMT_PUBLIC.class);
        lenient().when(signingPublic.toTpm()).thenReturn("signPub".getBytes(StandardCharsets.UTF_8));
        lenient().when(encryptionPublic.toTpm()).thenReturn("encPub".getBytes(StandardCharsets.UTF_8));

        CreatePrimaryResponse signingResponse = new CreatePrimaryResponse();
        signingResponse.handle = new TPM_HANDLE(0x81000001);
        signingResponse.outPublic = signingPublic;

        CreatePrimaryResponse encryptionResponse = new CreatePrimaryResponse();
        encryptionResponse.handle = new TPM_HANDLE(0x81000002);
        encryptionResponse.outPublic = encryptionPublic;

        setStaticField(tpmClass, "tpm", tpmMock);
        setStaticField(tpmClass, "signingPrimaryResponse", signingResponse);
        setStaticField(tpmClass, "encPrimaryResponse", encryptionResponse);

        Constructor<?> ctor = tpmClass.getDeclaredConstructor();
        ctor.setAccessible(true);
        ClientCryptoService tpmService = (ClientCryptoService) ctor.newInstance();

        TPMS_SIGNATURE_RSASSA rsassa = new TPMS_SIGNATURE_RSASSA(TPM_ALG_ID.SHA256,
                "sig".getBytes(StandardCharsets.UTF_8));
        when(tpmMock.Sign(any(TPM_HANDLE.class), any(byte[].class), any(TPMS_NULL_SIG_SCHEME.class),
                any(TPMT_TK_HASHCHECK.class))).thenReturn(rsassa);
        when(tpmMock.RSA_Decrypt(any(TPM_HANDLE.class), any(byte[].class), any(TPMS_NULL_ASYM_SCHEME.class), any(byte[].class)))
                .thenReturn("plain".getBytes(StandardCharsets.UTF_8));
        when(tpmMock.GetRandom(4)).thenReturn(new byte[] { 1, 2, 3, 4 });

        assertArrayEquals("sig".getBytes(StandardCharsets.UTF_8), tpmService.signData(sampleData));
        assertArrayEquals("plain".getBytes(StandardCharsets.UTF_8), tpmService.asymmetricDecrypt("cipher".getBytes()));

        Method randomMethod = tpmClass.getDeclaredMethod("generateRandomBytes", int.class);
        randomMethod.setAccessible(true);
        byte[] random = (byte[]) randomMethod.invoke(null, 4);
        assertArrayEquals(new byte[] { 1, 2, 3, 4 }, random);

        doThrow(new IOException("boom")).when(tpmMock).close();
        tpmService.closeSecurityInstance();

        setStaticField(tpmClass, "tpm", null);
        setStaticField(tpmClass, "signingPrimaryResponse", null);
        setStaticField(tpmClass, "encPrimaryResponse", null);
    }

    @Test
    public void testTpmGetSigningPublicPartInitializesCache() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Tpm tpmMock = mock(Tpm.class);
        setStaticField(tpmClass, "tpm", tpmMock);
        setStaticField(tpmClass, "signingPrimaryResponse", null);
        setStaticField(tpmClass, "encPrimaryResponse", null);

        CreatePrimaryResponse signingResponse = buildSigningPrimaryResponse();
        when(tpmMock.CreatePrimary(any(TPM_HANDLE.class), any(TPMS_SENSITIVE_CREATE.class),
                any(TPMT_PUBLIC.class), any(byte[].class), any(TPMS_PCR_SELECTION[].class)))
                .thenReturn(signingResponse);

        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
        byte[] publicPart = tpmService.getSigningPublicPart();

        assertArrayEquals(signingResponse.outPublic.toTpm(), publicPart);
        verify(tpmMock).CreatePrimary(any(TPM_HANDLE.class), any(TPMS_SENSITIVE_CREATE.class),
                any(TPMT_PUBLIC.class), any(byte[].class), any(TPMS_PCR_SELECTION[].class));

        resetTpmStatics(tpmClass);
    }

    @Test
    public void testTpmGetEncryptionPublicPartInitializesCache() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Tpm tpmMock = mock(Tpm.class);
        setStaticField(tpmClass, "tpm", tpmMock);
        setStaticField(tpmClass, "signingPrimaryResponse", null);
        setStaticField(tpmClass, "encPrimaryResponse", null);

        CreatePrimaryResponse encryptionResponse = buildEncryptionPrimaryResponse();
        when(tpmMock.CreatePrimary(any(TPM_HANDLE.class), any(TPMS_SENSITIVE_CREATE.class),
                any(TPMT_PUBLIC.class), isNull(), isNull()))
                .thenReturn(encryptionResponse);

        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
        byte[] publicPart = tpmService.getEncryptionPublicPart();

        assertArrayEquals(encryptionResponse.outPublic.toTpm(), publicPart);
        verify(tpmMock).CreatePrimary(any(TPM_HANDLE.class), any(TPMS_SENSITIVE_CREATE.class),
                any(TPMT_PUBLIC.class), isNull(), isNull());

        resetTpmStatics(tpmClass);
    }

    @Test
    public void testTpmSignDataThrowsWhenTpmNull() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Tpm tpmMock = mock(Tpm.class);
        setStaticField(tpmClass, "tpm", tpmMock);
        setStaticField(tpmClass, "signingPrimaryResponse", buildSigningPrimaryResponse());
        setStaticField(tpmClass, "encPrimaryResponse", buildEncryptionPrimaryResponse());

        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
        setStaticField(tpmClass, "tpm", null);

        try {
            tpmService.signData(sampleData);
            fail("Expected ClientCryptoException when TPM instance is null");
        } catch (ClientCryptoException expected) {
            // expected
        }

        try {
            tpmService.asymmetricDecrypt(sampleData);
            fail("Expected ClientCryptoException when TPM instance is null");
        } catch (ClientCryptoException expected) {
            // expected
        }

        resetTpmStatics(tpmClass);
    }

    @Test
    public void testTpmCloseSecurityInstanceWithNullTpmDoesNothing() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Tpm tpmMock = mock(Tpm.class);
        setStaticField(tpmClass, "tpm", tpmMock);
        setStaticField(tpmClass, "signingPrimaryResponse", buildSigningPrimaryResponse());
        setStaticField(tpmClass, "encPrimaryResponse", buildEncryptionPrimaryResponse());

        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
        setStaticField(tpmClass, "tpm", null);

        tpmService.closeSecurityInstance();

        resetTpmStatics(tpmClass);
    }

//    @Test
//    public void testTpmValidateSignaturePropagatesError() throws Exception {
//        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
//        Tpm tpmMock = mock(Tpm.class);
//        setStaticField(tpmClass, "tpm", tpmMock);
//        setStaticField(tpmClass, "signingPrimaryResponse", buildSigningPrimaryResponse());
//        setStaticField(tpmClass, "encPrimaryResponse", buildEncryptionPrimaryResponse());
//
//        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
//
//        try {
//            tpmService.validateSignature(new byte[0], sampleData);
//            fail("Expected exception for invalid signature input");
//        } catch (ClientCryptoException | IllegalArgumentException expected) {
//            expected.addSuppressed(expected);
//        }
//
//        resetTpmStatics(tpmClass);
//    }

    @Test
    public void testTpmSignDataThrowsWhenSignedDataNull() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Tpm tpmMock = mock(Tpm.class);
        setStaticField(tpmClass, "tpm", tpmMock);
        setStaticField(tpmClass, "signingPrimaryResponse", buildSigningPrimaryResponse());
        setStaticField(tpmClass, "encPrimaryResponse", buildEncryptionPrimaryResponse());

        when(tpmMock.Sign(any(TPM_HANDLE.class), any(byte[].class), any(TPMS_NULL_SIG_SCHEME.class),
                any(TPMT_TK_HASHCHECK.class))).thenReturn(null);

        ClientCryptoService tpmService = instantiateTpmService(tpmClass);

        try {
            tpmService.signData(sampleData);
            fail("Expected ClientCryptoException");
        } catch (ClientCryptoException ex) {
            assertEquals(ClientCryptoErrorConstants.CRYPTO_FAILED.getErrorCode(), ex.getErrorCode());
        }

        resetTpmStatics(tpmClass);
    }

//    @Test(expected = ClientCryptoException.class)
//    public void testTpmAsymmetricEncryptReturnsCiphertext() throws Exception {
//        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
//        Tpm tpmMock = mock(Tpm.class);
//        setStaticField(tpmClass, "tpm", tpmMock);
//        setStaticField(tpmClass, "signingPrimaryResponse", buildSigningPrimaryResponse());
//        setStaticField(tpmClass, "encPrimaryResponse", buildEncryptionPrimaryResponse());
//
//        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
//
//        byte[] cipher = tpmService.asymmetricEncrypt("cover".getBytes(StandardCharsets.UTF_8));
//        assertNotNull(cipher);
//        assertTrue(cipher.length > 0);
//
//        resetTpmStatics(tpmClass);
//    }

    @Test
    public void testTpmCloseSecurityInstanceInvokesClose() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Tpm tpmMock = mock(Tpm.class);
        setStaticField(tpmClass, "tpm", tpmMock);
        setStaticField(tpmClass, "signingPrimaryResponse", buildSigningPrimaryResponse());
        setStaticField(tpmClass, "encPrimaryResponse", buildEncryptionPrimaryResponse());

        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
        tpmService.closeSecurityInstance();

        verify(tpmMock).close();
        resetTpmStatics(tpmClass);
    }

    @Test
    public void testTpmGetSecretKeyViaReflection() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Method method = tpmClass.getDeclaredMethod("getSecretKey");
        method.setAccessible(true);
        Object result = method.invoke(null);
        assertNotNull(result);
    }

    @Test
    public void testTpmIsKernelModeTRMTrueBranch() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Tpm tpmMock = mock(Tpm.class);
        setStaticField(tpmClass, "tpm", tpmMock);
        setStaticField(tpmClass, "signingPrimaryResponse", buildSigningPrimaryResponse());
        setStaticField(tpmClass, "encPrimaryResponse", buildEncryptionPrimaryResponse());

        when(tpmMock._getDevice()).thenReturn(mock(TpmDeviceTbs.class));

        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
        Method method = tpmClass.getDeclaredMethod("isKernelModeTRM");
        method.setAccessible(true);
        assertTrue((Boolean) method.invoke(tpmService));

        resetTpmStatics(tpmClass);
    }

    @Test
    public void testTpmIsKernelModeTRMFalseBranch() throws Exception {
        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
        Tpm tpmMock = mock(Tpm.class);
        setStaticField(tpmClass, "tpm", tpmMock);
        setStaticField(tpmClass, "signingPrimaryResponse", buildSigningPrimaryResponse());
        setStaticField(tpmClass, "encPrimaryResponse", buildEncryptionPrimaryResponse());

        when(tpmMock._getDevice()).thenReturn((TpmDeviceBase) null);

        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
        Method method = tpmClass.getDeclaredMethod("isKernelModeTRM");
        method.setAccessible(true);
        assertFalse((Boolean) method.invoke(tpmService));

        resetTpmStatics(tpmClass);
    }

    @Test
    public void testClientCryptoFacadeValidateSignatureDefaultPath() throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(sampleData);
        byte[] signed = signature.sign();

        boolean verified = clientCryptoFacade.validateSignature(keyPair.getPublic().getEncoded(), signed, sampleData);
        assertTrue(verified);
    }

    @Test
    public void testClientCryptoFacadeDecryptFallbackPath() throws Exception {
        byte[] secret = new byte[symmetricKeyLength];
        byte[] iv = new byte[ivLength];
        byte[] aad = new byte[aadLength];
        byte[] cipher = "cipher".getBytes(StandardCharsets.UTF_8);
        when(clientCryptoService.asymmetricDecrypt(any(byte[].class))).thenReturn(secret);
        when(cryptoCore.symmetricDecrypt(any(SecretKey.class), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenThrow(new RuntimeException("primary"))
                .thenReturn(sampleData);

        byte[] payload = new byte[secret.length + iv.length + aad.length + cipher.length];
        System.arraycopy(secret, 0, payload, 0, secret.length);
        System.arraycopy(iv, 0, payload, secret.length, iv.length);
        System.arraycopy(aad, 0, payload, secret.length + iv.length, aad.length);
        System.arraycopy(cipher, 0, payload, secret.length + iv.length + aad.length, cipher.length);

        byte[] result = clientCryptoFacade.decrypt(payload);

        assertArrayEquals(sampleData, result);
        verify(cryptoCore, times(2)).symmetricDecrypt(any(SecretKey.class), any(byte[].class), any(byte[].class), any(byte[].class));
    }

//    @Test
//    public void testTpmAsymmetricEncryptPropagatesError() throws Exception {
//        Class<?> tpmClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.TPMClientCryptoServiceImpl");
//        Tpm tpmMock = mock(Tpm.class);
//        setStaticField(tpmClass, "tpm", tpmMock);
//        setStaticField(tpmClass, "signingPrimaryResponse", buildSigningPrimaryResponse());
//        setStaticField(tpmClass, "encPrimaryResponse", buildEncryptionPrimaryResponse());
//
//        ClientCryptoService tpmService = instantiateTpmService(tpmClass);
//
//        try {
//            tpmService.asymmetricEncrypt(sampleData);
//            fail("Expected ClientCryptoException for asymmetric encrypt with stubbed data");
//        } catch (ClientCryptoException expected) {
//            // expected
//        }
//
//        resetTpmStatics(tpmClass);
//    }

    private ClientCryptoService createLocalClientCryptoService() throws Exception {
        cleanKeysDirectory();
        Class<?> localClass = Class.forName("io.mosip.kernel.clientcrypto.service.impl.LocalClientCryptoServiceImpl");
        Constructor<?> ctor = localClass.getDeclaredConstructor(CryptoCoreSpec.class,
                org.springframework.context.ApplicationContext.class, Boolean.class, String.class);
        ctor.setAccessible(true);
        return (ClientCryptoService) ctor.newInstance(cryptoCore, applicationContext, false, "RESIDENT");
    }

    private ClientCryptoService instantiateTpmService(Class<?> tpmClass) throws Exception {
        Constructor<?> ctor = tpmClass.getDeclaredConstructor();
        ctor.setAccessible(true);
        return (ClientCryptoService) ctor.newInstance();
    }

    private void injectField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private void setStaticField(Class<?> clazz, String fieldName, Object value) throws Exception {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(null, value);
    }

    private void cleanKeysDirectory() throws IOException {
        Path keysDir = Paths.get(ClientCryptoManagerConstant.KEY_PATH, ClientCryptoManagerConstant.KEYS_DIR);
        if (Files.exists(keysDir)) {
            Files.walk(keysDir)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(java.io.File::delete);
        }
    }

    private CreatePrimaryResponse buildSigningPrimaryResponse() {
        CreatePrimaryResponse response = new CreatePrimaryResponse();
        response.handle = new TPM_HANDLE(0x81010001);
        response.outPublic = buildSigningPublicArea();
        return response;
    }

    private CreatePrimaryResponse buildEncryptionPrimaryResponse() {
        CreatePrimaryResponse response = new CreatePrimaryResponse();
        response.handle = new TPM_HANDLE(0x81010002);
        response.outPublic = buildEncryptionPublicArea();
        return response;
    }

    private TPMT_PUBLIC buildSigningPublicArea() {
        return new TPMT_PUBLIC(TPM_ALG_ID.SHA1,
                new TPMA_OBJECT(TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sign,
                        TPMA_OBJECT.sensitiveDataOrigin, TPMA_OBJECT.userWithAuth),
                new byte[0],
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL),
                        new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256), 2048, 65537),
                new TPM2B_PUBLIC_KEY_RSA(rsaModulusBytes()));
    }

    private TPMT_PUBLIC buildEncryptionPublicArea() {
        return new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent,
                        TPMA_OBJECT.decrypt, TPMA_OBJECT.sensitiveDataOrigin, TPMA_OBJECT.userWithAuth),
                new byte[0],
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL),
                        new TPMS_ENC_SCHEME_OAEP(TPM_ALG_ID.SHA256), 2048, 65537),
                new TPM2B_PUBLIC_KEY_RSA(rsaModulusBytes()));
    }

    private byte[] rsaModulusBytes() {
        byte[] modulus = ((RSAPublicKey) keyPair.getPublic()).getModulus().toByteArray();
        byte[] normalized = new byte[256];
        if (modulus.length >= 256) {
            System.arraycopy(modulus, modulus.length - 256, normalized, 0, 256);
        } else {
            System.arraycopy(modulus, 0, normalized, 256 - modulus.length, modulus.length);
        }
        return normalized;
    }

    private void resetTpmStatics(Class<?> tpmClass) throws Exception {
        setStaticField(tpmClass, "tpm", null);
        setStaticField(tpmClass, "signingPrimaryResponse", null);
        setStaticField(tpmClass, "encPrimaryResponse", null);
    }
}
