package io.mosip.kernel.crypto.jce.test;

import static org.junit.Assert.assertNotNull;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import io.mosip.kernel.crypto.jce.core.CryptoCore;

@SpringBootTest
@RunWith(SpringRunner.class)
public class AsymmetricDecryptTest {

    @Autowired
    private CryptoCore cryptoCore;

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private byte[] testData = "test data".getBytes();

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "JCE");
    }

    @Test
    public void testAsymmetricDecryptWithPrivateKey() {
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);
        byte[] result = cryptoCore.asymmetricDecrypt(privateKey, encrypted);
        assertNotNull(result);
    }

    @Test
    public void testAsymmetricDecryptWithPrivateAndPublicKey() {
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);
        byte[] result = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encrypted);
        assertNotNull(result);
    }

    @Test
    public void testAsymmetricDecryptWithStoreType() {
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);
        byte[] result = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encrypted, null);
        assertNotNull(result);
    }

    @Test
    public void testAsymmetricDecryptWithNullPublicKey() {
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);
        byte[] result = cryptoCore.asymmetricDecrypt(privateKey, null, encrypted);
        assertNotNull(result);
    }

    @Test(expected = InvalidDataException.class)
    public void testAsymmetricDecryptWithInvalidData() {
        cryptoCore.asymmetricDecrypt(privateKey, "invalid".getBytes());
    }

    @Test
    public void testAsymmetricDecryptWithPKCS11KeystoreType() {
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "PKCS11");
        
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);

        byte[] result1 = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encrypted, null);
        assertNotNull(result1);

        byte[] result2 = cryptoCore.asymmetricDecrypt(privateKey, null, encrypted, null);
        assertNotNull(result2);

        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "JCE");
    }

    @Test
    public void testAsymmetricDecryptPKCS11SingleParam() {
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "PKCS11");
        
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);
        byte[] result = cryptoCore.asymmetricDecrypt(privateKey, encrypted);
        assertNotNull(result);
        
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "JCE");
    }

    @Test
    public void testAsymmetricDecryptPKCS11TwoParams() {
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "PKCS11");
        
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);

        byte[] result1 = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encrypted);
        assertNotNull(result1);

        byte[] result2 = cryptoCore.asymmetricDecrypt(privateKey, null, encrypted);
        assertNotNull(result2);
        
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "JCE");
    }

    @Test
    public void testAsymmetricDecryptPKCS11WithStoreType() {
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "PKCS11");
        
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);
        byte[] result1 = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encrypted, "SunJCE");
        assertNotNull(result1);

        byte[] result2 = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encrypted, null);
        assertNotNull(result2);
        
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "JCE");
    }

    @Test
    public void testAsymmetricDecryptPKCS11PaddingLogic() throws Exception {
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "PKCS11");

        ReflectionTestUtils.setField(cryptoCore, "asymmetricKeyLength", 1024);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair smallKeyPair = keyGen.generateKeyPair();
        RSAPrivateKey smallPrivateKey = (RSAPrivateKey) smallKeyPair.getPrivate();
        RSAPublicKey smallPublicKey = (RSAPublicKey) smallKeyPair.getPublic();
        
        byte[] encrypted = cryptoCore.asymmetricEncrypt(smallPublicKey, testData);
        byte[] result = cryptoCore.asymmetricDecrypt(smallPrivateKey, encrypted);
        assertNotNull(result);

        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "JCE");
        ReflectionTestUtils.setField(cryptoCore, "asymmetricKeyLength", 2048);
    }

    @Test
    public void testJceAsymmetricDecryptWithStoreType() {
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "JCE");
        
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);

        byte[] result = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encrypted, "SunJCE");
        assertNotNull(result);
    }

    @Test
    public void testJceAsymmetricDecryptWithoutStoreType() {
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "JCE");
        
        byte[] encrypted = cryptoCore.asymmetricEncrypt(publicKey, testData);

        byte[] result = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encrypted, null);
        assertNotNull(result);
    }

    @Test(expected = InvalidDataException.class)
    public void testAsymmetricDecryptWithEmptyData() {
        cryptoCore.asymmetricDecrypt(privateKey, new byte[0]);
    }

    @Test(expected = InvalidDataException.class)
    public void testUnpadOAEPPaddingException() {
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "PKCS11");
        byte[] invalidData = new byte[256];
        Arrays.fill(invalidData, (byte) 0xFF);
        
        cryptoCore.asymmetricDecrypt(privateKey, invalidData);
        ReflectionTestUtils.setField(cryptoCore, "keystoreType", "JCE");
    }
}