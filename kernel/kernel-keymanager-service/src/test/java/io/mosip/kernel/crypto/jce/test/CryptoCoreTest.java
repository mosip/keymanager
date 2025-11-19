package io.mosip.kernel.crypto.jce.test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import io.mosip.kernel.core.crypto.exception.InvalidKeyException;
import io.mosip.kernel.core.crypto.exception.SignatureException;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class CryptoCoreTest {

	private static final String MOCKAAD = "MOCKAAD";

	@Autowired
	private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

	@Autowired
	private KeymanagerUtil keymanagerUtil;

	private KeyPair rsaPair;

	private byte[] data;

	private byte[] keyBytes;

	private final SecureRandom random = new SecureRandom();

	private String certificate = "-----BEGIN CERTIFICATE-----\n" +
			"MIIDbDCCAlSgAwIBAgIUTW8ScXGEgz/C0o7xnAsBmd3P8hswDQYJKoZIhvcNAQEL\n" +
			"BQAwbzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5nYWx1\n" +
			"cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRowGAYDVQQD\n" +
			"DBFQTVMtcm9vdC10ZXN0Y2FzZTAgFw0yNTEwMTMxMzQzMzZaGA8yMTI1MTAxMzEz\n" +
			"NDMzNlowbzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCZW5n\n" +
			"YWx1cnUxDjAMBgNVBAoMBU1vc2lwMRMwEQYDVQQLDApLZXltYW5hZ2VyMRowGAYD\n" +
			"VQQDDBFQTVMtcm9vdC10ZXN0Y2FzZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
			"AQoCggEBANZqa/+RIVKaoIiQ11pFXOCL1NgOd6F1a98KIWU3ZZ8Kh/CjPN5V5QN/\n" +
			"pqLX5/4+Zw4tJJqsruQmCz76LCLFREuoWTByNtnKZDni1quNRkcz7uiKeOLFHzk4\n" +
			"QODDF4BfefaQElOLSMdHueoKgWBor+/E9aK8+vvk3kPOtC67RmhWCJ5TAI19kCaY\n" +
			"lBrneAx+JmQxJ8sAHszErHxjdlEIUNSoU4GbIrgw4C8dtdG6yVb3arM9+kCsa0hg\n" +
			"JGYCW8igi8P0yyUoeGpi86ZiYjiIVGZS7dmZM/vGun+JjaHtTlBCvCsMxVstrhMZ\n" +
			"AgVZouiaXgmbvubSXDuBBOL6pDRWFocCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
			"irKsATgEedB8IoD4WeGW7KRuPxT6iow4yQUf9kODEYzsNKRdvowUD97MnORaF1ns\n" +
			"EtA+vTfutktHHMhnBNfuFyZFsZCqq3skbRGst9RjxokznljE/OZc0q+24Hm9dRfZ\n" +
			"SMBYWPEnFQzpvPmOexLwRRwt6EGrZPWUh22NGYLbJR22CP5wTgsUKwA6MHcAVVTS\n" +
			"5+WcxMD0OMoRX5LIlFLUSyyZb6POs/lsta7+fr2FU84FNLrooz0Q+8/QzTpW/XND\n" +
			"N3yr7o9LBHFXwVB+Fb6ow4/r9hPuBFg58FM+wQt5AJ5cz/LeOKsVpDJ8Bvuodrxa\n" +
			"vb31TtM0csPVLODrpnNZyA==\n" +
			"-----END CERTIFICATE-----";

	@Before
	public void init() throws java.security.NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048, random);
		rsaPair = generator.generateKeyPair();
		data = "test".getBytes();
		keyBytes = new byte[16];
		random.nextBytes(keyBytes);

	}

	private SecretKeySpec setSymmetricUp(int length, String algo) throws java.security.NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		byte[] keyBytes = new byte[length];
		random.nextBytes(keyBytes);
		return new SecretKeySpec(keyBytes, algo);
	}

	@Test
	public void testAsymmetricPublicEncrypt() {
		assertThat(cryptoCore.asymmetricEncrypt(rsaPair.getPublic(), data), isA(byte[].class));
	}

	@Test
	public void testAESSymmetricEncrypt() throws java.security.NoSuchAlgorithmException {
		assertThat(cryptoCore.symmetricEncrypt(setSymmetricUp(32, "AES"), data, null, MOCKAAD.getBytes()),
				isA(byte[].class));
	}

	@Test
	public void testAESSymmetricSaltEncrypt() throws java.security.NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		byte[] keyBytes = new byte[16];
		random.nextBytes(keyBytes);
		assertThat(cryptoCore.symmetricEncrypt(setSymmetricUp(32, "AES"), data, keyBytes, MOCKAAD.getBytes()),
				isA(byte[].class));
	}

	@Test(expected = NullPointerException.class)
	public void testAESSymmetricEncryptNullKey() throws java.security.NoSuchAlgorithmException {
		cryptoCore.symmetricEncrypt(null, data, MOCKAAD.getBytes());
	}

	@Test(expected = InvalidKeyException.class)
	public void testAESSymmetricEncryptInvalidKey() throws java.security.NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		byte[] keyBytes = new byte[15];
		random.nextBytes(keyBytes);
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
		cryptoCore.symmetricEncrypt(secretKeySpec, data, MOCKAAD.getBytes());
	}

	@Test(expected = InvalidKeyException.class)
	public void testAESSymmetricEncryptSaltInvalidKey() throws java.security.NoSuchAlgorithmException {
		SecretKeySpec secretKeySpec = setSymmetricUp(15, "AES");
		cryptoCore.symmetricEncrypt(secretKeySpec, data, keyBytes, MOCKAAD.getBytes());
	}

	@Test(expected = InvalidKeyException.class)
	public void testAsymmetricPublicInvalidKeyEncrypt() throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
		generator.initialize(2048, random);
		KeyPair invalidKeyPair = generator.generateKeyPair();
		assertThat(cryptoCore.asymmetricEncrypt(invalidKeyPair.getPublic(), data), isA(byte[].class));
	}

	@Test
	public void testHash() throws NoSuchAlgorithmException, InvalidKeySpecException {
		assertThat(cryptoCore.hash(data, keyBytes), isA(String.class));
	}

	@Test
	public void testSign() throws NoSuchAlgorithmException, InvalidKeySpecException {
		assertThat(cryptoCore.sign(data, rsaPair.getPrivate()), isA(String.class));
	}

	@Test(expected = SignatureException.class)
	public void testSignInvalidKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
		generator.initialize(2048, random);
		KeyPair invalidKeyPair = generator.generateKeyPair();
		assertThat(cryptoCore.sign(data, invalidKeyPair.getPrivate()), isA(String.class));
	}

	@Test
	public void testVerify() throws NoSuchAlgorithmException, InvalidKeySpecException {
		String signature = cryptoCore.sign(data, rsaPair.getPrivate());
		assertThat(cryptoCore.verifySignature(data, signature, rsaPair.getPublic()), is(true));
	}

	@Test(expected = SignatureException.class)
	public void testVerifySignatureException() throws NoSuchAlgorithmException, InvalidKeySpecException {
		assertThat(cryptoCore.verifySignature(data, "Invaliddata", rsaPair.getPublic()), is(true));
	}

	@Test(expected = SignatureException.class)
	public void testVerifySignatureNullException() throws NoSuchAlgorithmException, InvalidKeySpecException {
		assertThat(cryptoCore.verifySignature(data, null, rsaPair.getPublic()), is(true));
	}

	@Test(expected = SignatureException.class)
	public void testVerifyInvalidKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
		generator.initialize(2048, random);
		KeyPair invalidKeyPair = generator.generateKeyPair();
		String signature = cryptoCore.sign(data, rsaPair.getPrivate());
		assertThat(cryptoCore.verifySignature(data, signature, invalidKeyPair.getPublic()), is(true));
	}

	@Test
	public void testRandom() throws NoSuchAlgorithmException, InvalidKeySpecException {
		assertThat(cryptoCore.random(), isA(SecureRandom.class));
	}

	@Test
	public void testAsymmetricDecrypt() {
		byte[] encryptedData = cryptoCore.asymmetricEncrypt(rsaPair.getPublic(), data);
		assertThat(cryptoCore.asymmetricDecrypt(rsaPair.getPrivate(), encryptedData), isA(byte[].class));
	}

	@Test
	public void testAESSymmetricDecrypt() throws java.security.NoSuchAlgorithmException {
		SecretKeySpec secretKeySpec = setSymmetricUp(32, "AES");
		byte[] encryptedData = cryptoCore.symmetricEncrypt(secretKeySpec, data, MOCKAAD.getBytes());
		assertThat(cryptoCore.symmetricDecrypt(secretKeySpec, encryptedData, null, MOCKAAD.getBytes()),
				isA(byte[].class));
	}

	@Test
	public void testAESSymmetricSaltDecrypt() throws java.security.NoSuchAlgorithmException {
		SecretKeySpec secretKeySpec = setSymmetricUp(32, "AES");
		byte[] encryptedData = cryptoCore.symmetricEncrypt(secretKeySpec, data, MOCKAAD.getBytes(), keyBytes);
		assertThat(cryptoCore.symmetricDecrypt(secretKeySpec, encryptedData, MOCKAAD.getBytes(), keyBytes),
				isA(byte[].class));
	}

	@Test(expected = NullPointerException.class)
	public void testAESSymmetricDecryptInvalidKey() throws java.security.NoSuchAlgorithmException {
		SecretKeySpec secretKeySpec = setSymmetricUp(32, "AES");
		byte[] encryptedData = cryptoCore.symmetricEncrypt(secretKeySpec, data, MOCKAAD.getBytes());
		cryptoCore.symmetricDecrypt(null, encryptedData, MOCKAAD.getBytes());
	}

	@Test(expected = InvalidDataException.class)
	public void testAESSymmetricDecryptInvalidDataArrayIndexOutOfBounds()
			throws java.security.NoSuchAlgorithmException {
		cryptoCore.symmetricDecrypt(setSymmetricUp(32, "AES"), "aa".getBytes(), MOCKAAD.getBytes());
	}

	@Test(expected = InvalidDataException.class)
	public void testAESSymmetricDecryptInvalidDataIllegalBlockSize() throws java.security.NoSuchAlgorithmException {
		cryptoCore.symmetricDecrypt(setSymmetricUp(32, "AES"), new byte[121], MOCKAAD.getBytes());
	}

	@Test(expected = InvalidKeyException.class)
	public void testAESSymmetricDecryptInvalidKeyLength() throws java.security.NoSuchAlgorithmException {
		SecretKeySpec secretKeySpec = setSymmetricUp(32, "AES");
		byte[] encryptedData = cryptoCore.symmetricEncrypt(secretKeySpec, data, MOCKAAD.getBytes());
		cryptoCore.symmetricDecrypt(setSymmetricUp(15, "AES"), encryptedData, null, MOCKAAD.getBytes());
	}

	@Test(expected = InvalidKeyException.class)
	public void testAESSymmetricDecryptSaltInvalidKeyLength() throws java.security.NoSuchAlgorithmException {
		SecretKeySpec secretKeySpec = setSymmetricUp(32, "AES");
		byte[] encryptedData = cryptoCore.symmetricEncrypt(secretKeySpec, data, MOCKAAD.getBytes());
		cryptoCore.symmetricDecrypt(setSymmetricUp(15, "AES"), encryptedData, keyBytes, MOCKAAD.getBytes());
	}

	@Test(expected = InvalidDataException.class)
	public void testRSAPKS1AsymmetricPrivateDecryptInvalidDataIllegalBlockSize() {
		cryptoCore.asymmetricDecrypt(rsaPair.getPrivate(), new byte[121]);
	}

	@Test(expected = InvalidKeyException.class)
	public void testAsymmetricPublicInvalidKeyDecrypt() throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
		generator.initialize(2048, random);
		KeyPair invalidKeyPair = generator.generateKeyPair();
		byte[] encryptedData = cryptoCore.asymmetricEncrypt(rsaPair.getPublic(), data);
		assertThat(cryptoCore.asymmetricDecrypt(invalidKeyPair.getPrivate(), rsaPair.getPublic(), encryptedData), isA(byte[].class));
	}

	@Test
	public void signTest() {
		X509Certificate x509Certificate = (X509Certificate) keymanagerUtil.convertToCertificate(certificate);
		String result = cryptoCore.sign(data, rsaPair.getPrivate(), x509Certificate);
		Assert.assertNotNull(result);
	}

	@Test
	public void verifySignatureTest() {
		X509Certificate x509Certificate = (X509Certificate) keymanagerUtil.convertToCertificate(certificate);
		String signature = cryptoCore.sign(data, rsaPair.getPrivate(), x509Certificate);
		boolean result = cryptoCore.verifySignature(signature);
		Assert.assertFalse(result);
	}

	@Test(expected = SignatureException.class)
	public void verifySignatureException() {
		cryptoCore.verifySignature("");
	}

	@Test(expected = SignatureException.class)
	public void verifySignatureInvalidSign() {
		cryptoCore.verifySignature("Invalid Signature");
	}
}
