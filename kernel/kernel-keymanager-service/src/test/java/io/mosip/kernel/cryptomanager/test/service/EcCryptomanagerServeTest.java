package io.mosip.kernel.cryptomanager.test.service;

import io.mosip.kernel.core.crypto.exception.InvalidKeyException;
import io.mosip.kernel.core.exception.NoSuchAlgorithmException;
import io.mosip.kernel.cryptomanager.service.EcCryptomanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
@TestPropertySource(properties = {
        "mosip.kernel.keygenerator.asymmetric-algorithm-name=EC",
        "mosip.kernel.keygenerator.ecc-curve-name=secp256k1",
        "mosip.kernel.data-key-splitter=#MOSIP_SPLITTER#"
})
public class EcCryptomanagerServeTest {

    @Autowired
    private EcCryptomanagerService ecCryptomanagerService;

    @Value("${mosip.kernel.keygenerator.ecc-curve-name}")
    private String curveNameK1;

    private static final String CURVE_SECP256R1 = "secp256r1";

    @BeforeClass
    public static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testAsymmetricEcEncryptDecrypt_Secp256k1() throws Exception {
        // Uses the property value secp256k1
        String curveName = curveNameK1;
        KeyPair keyPair = generateKeyPair("EC", curveName);

        String data = "Test Data for secp256k1";
        byte[] dataBytes = data.getBytes();

        byte[] encrypted = ecCryptomanagerService.asymmetricEcEncrypt(keyPair.getPublic(), dataBytes, curveName);
        Assert.assertNotNull(encrypted);

        byte[] decrypted = ecCryptomanagerService.asymmetricEcDecrypt(keyPair.getPrivate(), encrypted, null, curveName);
        Assert.assertArrayEquals(dataBytes, decrypted);
    }

    @Test
    public void testAsymmetricEcEncryptDecrypt_Secp256r1() throws Exception {
        String curveName = CURVE_SECP256R1;
        KeyPair keyPair = generateKeyPair("EC", curveName);

        String data = "Test Data for secp256r1";
        byte[] dataBytes = data.getBytes();

        byte[] encrypted = ecCryptomanagerService.asymmetricEcEncrypt(keyPair.getPublic(), dataBytes, curveName);
        Assert.assertNotNull(encrypted);

        byte[] decrypted = ecCryptomanagerService.asymmetricEcDecrypt(keyPair.getPrivate(), encrypted, null, curveName);
        Assert.assertArrayEquals(dataBytes, decrypted);
    }

    @Test
    public void testAsymmetricEcEncryptDecrypt_X25519() throws Exception {
        String curveName = "X25519";
        KeyPair keyPair = generateKeyPair("X25519", null);

        String data = "Test Data for X25519";
        byte[] dataBytes = data.getBytes();

        byte[] encrypted = ecCryptomanagerService.asymmetricEcEncrypt(keyPair.getPublic(), dataBytes, curveName);
        Assert.assertNotNull(encrypted);

        byte[] decrypted = ecCryptomanagerService.asymmetricEcDecrypt(keyPair.getPrivate(), encrypted, null, curveName);
        Assert.assertArrayEquals(dataBytes, decrypted);
    }

    @Test
    public void testAsymmetricEcEncryptWithIVAndAAD() throws Exception {
        String curveName = curveNameK1;
        KeyPair keyPair = generateKeyPair("EC", curveName);

        String data = "Test Data with IV and AAD";
        byte[] dataBytes = data.getBytes();
        byte[] aad = "Additional Data".getBytes();
        byte[] iv = new byte[12]; // GCMNonce
        new SecureRandom().nextBytes(iv);

        byte[] encrypted = ecCryptomanagerService.asymmetricEcEncrypt(keyPair.getPublic(), dataBytes, iv, aad,
                curveName);
        Assert.assertNotNull(encrypted);

        byte[] decrypted = ecCryptomanagerService.asymmetricEcDecrypt(keyPair.getPrivate(), encrypted, aad, curveName);
        Assert.assertArrayEquals(dataBytes, decrypted);
    }

    @Test
    public void testEncrypt_NullKey_ThrowsException() {
        String data = "Test";
        assertThrows(NullPointerException.class, () -> {
            ecCryptomanagerService.asymmetricEcEncrypt(null, data.getBytes(), curveNameK1);
        });
    }

    @Test
    public void testEncrypt_InvalidData_ThrowsException() {
        KeyPair keyPair;
        try {
            keyPair = generateKeyPair("EC", curveNameK1);
            // VerifyData usually throws IllegalArgumentException or specific runtime
            // exception
            assertThrows(RuntimeException.class, () -> {
                ecCryptomanagerService.asymmetricEcEncrypt(keyPair.getPublic(), null, curveNameK1);
            });
        } catch (Exception e) {
            Assert.fail("Setup failed");
        }
    }

    @Test
    public void testDecrypt_NullKey_ThrowsException() {
        String data = "Test";
        assertThrows(NullPointerException.class, () -> {
            ecCryptomanagerService.asymmetricEcDecrypt(null, data.getBytes(), null, curveNameK1);
        });
    }

    @Test
    public void testDecrypt_CorruptedEphemeralKey_ThrowsInvalidKeyException() throws Exception {
        // Covers InvalidKeySpecException catch block in getEphemeralPublicKey
        KeyPair keyPair = generateKeyPair("EC", curveNameK1);
        String data = "Test Data";
        byte[] encrypted = ecCryptomanagerService.asymmetricEcEncrypt(keyPair.getPublic(), data.getBytes(),
                curveNameK1);

        // Corrupt the end of the message where ephemeral key likely resides
        encrypted[encrypted.length - 1] ^= 0xFF;
        assertThrows(InvalidKeyException.class, () -> {
            ecCryptomanagerService.asymmetricEcDecrypt(keyPair.getPrivate(), encrypted, null, curveNameK1);
        });
    }

    @Test
    public void testEncrypt_InvalidSymmetricAlgo_ThrowsNoSuchAlgorithmException() throws Exception {
        KeyPair keyPair = generateKeyPair("EC", curveNameK1);
        String data = "Test";

        Object originalAlgo = ReflectionTestUtils.getField(ecCryptomanagerService, "symmetricAlgorithmName");
        ReflectionTestUtils.setField(ecCryptomanagerService, "symmetricAlgorithmName", "INVALID_ALGO");

        try {
            assertThrows(NoSuchAlgorithmException.class, () -> {
                ecCryptomanagerService.asymmetricEcEncrypt(keyPair.getPublic(), data.getBytes(), curveNameK1);
            });
        } finally {
            ReflectionTestUtils.setField(ecCryptomanagerService, "symmetricAlgorithmName", originalAlgo);
        }
    }

    @Test
    public void testEncrypt_IncompatibleSymmetricAlgo_ThrowsInvalidKeyException() throws Exception {
        // Covers InvalidKeyException / InvalidAlgorithmParameterException catch blocks
        KeyPair keyPair = generateKeyPair("EC", curveNameK1);
        String data = "Test";

        Object originalAlgo = ReflectionTestUtils.getField(ecCryptomanagerService, "symmetricAlgorithmName");

        // AES/ECB/PKCS5Padding does not accept GCMParameterSpec ->
        // InvalidAlgorithmParameterException -> InvalidKeyException
        ReflectionTestUtils.setField(ecCryptomanagerService, "symmetricAlgorithmName", "AES/ECB/PKCS5Padding");

        try {
            assertThrows(InvalidKeyException.class, () -> {
                ecCryptomanagerService.asymmetricEcEncrypt(keyPair.getPublic(), data.getBytes(), curveNameK1);
            });
        } finally {
            ReflectionTestUtils.setField(ecCryptomanagerService, "symmetricAlgorithmName", originalAlgo);
        }
    }

    private KeyPair generateKeyPair(String algorithm, String curveName) throws Exception {
        KeyPairGenerator keyPairGenerator;
        if ("X25519".equals(algorithm)) {
            keyPairGenerator = KeyPairGenerator.getInstance("X25519", "BC");
            keyPairGenerator.initialize(new NamedParameterSpec("X25519"));
        } else {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");
            keyPairGenerator.initialize(new ECGenParameterSpec(curveName));
        }
        return keyPairGenerator.generateKeyPair();
    }
}
