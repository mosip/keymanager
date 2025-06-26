package io.mosip.kernel.cryptomanager.test.service;

import io.mosip.kernel.cryptomanager.service.EcCryptoOperation;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.Assert.*;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class EcCryptoOperationTest {

    @Value("${mosip.kernel.keygenerator.ecc-curve-name:SECP256R1}")
    private String ecCurveName;

    @Autowired
    private EcCryptoOperation service;

    private final String privateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCC6m5SEHQms8YoFUfABl3P918oNQwIJeGDukOeNV6e8Hw==";
    public final String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvMnarFay31WXcB/xsxBEOccl6+qJ88ctrzF9Rj9VqrLXk0Camh5x04cuA2cI9V8UWx9EhvPV7Wg4oS2aGs29Kg==";
    private final byte[] data = "QmFzZSA2NCBmb3JtYXQ=".getBytes();
    private final String base64EncryptedData = "x5TIYJ2+tpoAEEcMNfHQ9lLmmQyCEMpPcWZ5X98wW2yxx92J3ISENoUQPJ0utHSkI0tFWV9TUExJVFRFUiMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARauvM+h+aCtlD5la3jG4A3QvLhol+pfO8eWpznB5YtegnMR2SYlTEQVrLrMRzMhyw9S3idYGZsvKxYUsSpZ946";
    private byte[] encryptedData = Base64.getDecoder().decode(base64EncryptedData);

    @Test
    public void testAsymmetricEcEncrypt() throws Exception {
        byte[] result = service.asymmetricEcEncrypt(convertBase64ToECPublicKey(publicKey), data, ecCurveName);
        assertNotNull(result);
    }

    @Test
    public void testAsymmetricEcDecrypt() throws Exception {
        byte[] result = service.asymmetricEcDecrypt(convertBase64ToECPrivateKey(privateKey), encryptedData, null, ecCurveName);
        assertNotNull(result);
        assertArrayEquals(data, result);
    }

    @Test(expected = io.mosip.kernel.core.crypto.exception.InvalidKeyException.class)
    public void testInvalidKeyException() {
        service.asymmetricEcEncrypt(null, "data".getBytes(), null, null, ecCurveName);
        service.asymmetricEcDecrypt(null, encryptedData, null, ecCurveName);
    }

    @Test(expected = java.lang.NullPointerException.class)
    public void testNullPointerException() throws Exception {
        service.asymmetricEcEncrypt(convertBase64ToECPublicKey(publicKey), data, "INVALID_CURVE");
        service.asymmetricEcDecrypt(convertBase64ToECPrivateKey(privateKey), encryptedData, null, "INVALID_CURVE");
    }

    public static PublicKey convertBase64ToECPublicKey(String base64PublicKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64PublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return keyFactory.generatePublic(keySpec);
    }

    // Convert Base64 Private Key (String) to PrivateKey Object
    public static PrivateKey convertBase64ToECPrivateKey(String base64PrivateKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64PrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return keyFactory.generatePrivate(keySpec);
    }
}
