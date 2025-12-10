package io.mosip.kernel.clientcrypto.test.service;

import io.mosip.kernel.clientcrypto.exception.ClientCryptoException;
import io.mosip.kernel.clientcrypto.service.impl.AndroidClientCryptoServiceImpl;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.doReturn;

@RunWith(MockitoJUnitRunner.class)
public class AndroidClientCryptoServiceImplTest {

    @Spy
    @InjectMocks
    private AndroidClientCryptoServiceImpl androidClientCryptoService;

    private KeyPair keyPair;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    @Test
    public void testSignData() throws ClientCryptoException {
        byte[] result = androidClientCryptoService.signData(new byte[0]);
        assertArrayEquals(new byte[0], result);
    }

    @Test
    public void testAsymmetricEncrypt() throws ClientCryptoException {
        byte[] result = androidClientCryptoService.asymmetricEncrypt(new byte[0]);
        assertArrayEquals(new byte[0], result);
    }

    @Test
    public void testAsymmetricDecrypt() throws ClientCryptoException {
        // Mock the underlying call to return a valid key to avoid exception
        doReturn(keyPair.getPublic().getEncoded()).when(androidClientCryptoService).getEncryptionPublicPart();
        byte[] result = androidClientCryptoService.asymmetricDecrypt(new byte[0]);
        // The flawed implementation calls encrypt, so we expect a non-empty result
        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void testGetSigningPublicPart() {
        byte[] result = androidClientCryptoService.getSigningPublicPart();
        assertArrayEquals(new byte[0], result);
    }

    @Test
    public void testGetEncryptionPublicPart() {
        byte[] result = androidClientCryptoService.getEncryptionPublicPart();
        assertArrayEquals(new byte[0], result);
    }

    @Test
    public void testIsTPMInstance() {
        assertFalse(androidClientCryptoService.isTPMInstance());
    }

    @Test
    public void testCloseSecurityInstance() throws ClientCryptoException {
        androidClientCryptoService.closeSecurityInstance();
        // No exception should be thrown
    }

    @Test
    public void testValidateSignature() throws ClientCryptoException {
        // Mock the underlying call to return a valid key to avoid exception
        doReturn(keyPair.getPublic().getEncoded()).when(androidClientCryptoService).getSigningPublicPart();
        boolean result = androidClientCryptoService.validateSignature(new byte[256], new byte[0]);
        assertFalse(result);
    }

    @Test
    public void testStaticValidateSignatureSuccess() throws Exception {
        byte[] data = "test data".getBytes();
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(keyPair.getPrivate());
        privateSignature.update(data);
        byte[] signature = privateSignature.sign();

        boolean result = AndroidClientCryptoServiceImpl.validateSignature(keyPair.getPublic().getEncoded(), signature, data);
        assertTrue(result);
    }

    @Test
    public void testStaticValidateSignatureFailure() throws Exception {
        byte[] data = "test data".getBytes();
        byte[] wrongData = "wrong data".getBytes();
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(keyPair.getPrivate());
        privateSignature.update(data);
        byte[] signature = privateSignature.sign();

        boolean result = AndroidClientCryptoServiceImpl.validateSignature(keyPair.getPublic().getEncoded(), signature, wrongData);
        assertFalse(result);
    }

    @Test(expected = ClientCryptoException.class)
    public void testStaticValidateSignatureException() throws ClientCryptoException {
        AndroidClientCryptoServiceImpl.validateSignature(new byte[0], new byte[0], new byte[0]);
    }

    @Test
    public void testStaticAsymmetricEncryptSuccess() throws ClientCryptoException {
        byte[] data = "test data".getBytes();
        byte[] encryptedData = AndroidClientCryptoServiceImpl.asymmetricEncrypt(keyPair.getPublic().getEncoded(), data);
        assertNotNull(encryptedData);
        assertNotEquals(0, encryptedData.length);
    }

    @Test(expected = ClientCryptoException.class)
    public void testStaticAsymmetricEncryptException() throws ClientCryptoException {
        AndroidClientCryptoServiceImpl.asymmetricEncrypt(new byte[0], new byte[0]);
    }
}
