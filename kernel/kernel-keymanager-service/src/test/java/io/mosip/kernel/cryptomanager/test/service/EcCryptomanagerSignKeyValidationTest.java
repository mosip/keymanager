package io.mosip.kernel.cryptomanager.test.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.junit.BeforeClass;
import org.junit.Test;

import io.mosip.kernel.cryptomanager.constant.CryptomanagerErrorCode;
import io.mosip.kernel.cryptomanager.exception.CryptoManagerSerivceException;
import io.mosip.kernel.cryptomanager.service.impl.EcCryptomanagerServiceImpl;

/**
 * Ed25519/EdDSA keys are signing-only; EC encryption/decryption must reject them with
 * KER-CRY-018 instead of failing later with "unknown curve name: Ed25519".
 */
public class EcCryptomanagerSignKeyValidationTest {

	private static final byte[] DATA = "data".getBytes(StandardCharsets.UTF_8);
	private static final String EXPECTED_MESSAGE = "Encryption is not supported with Ed25519 key. Ed25519 is a signing-only key; "
			+ "use an X25519 or EC (SECP256R1/SECP256K1) key for encryption.";

	private static KeyPair ed25519KeyPair;

	private final EcCryptomanagerServiceImpl ecCryptomanagerService = new EcCryptomanagerServiceImpl();

	@BeforeClass
	public static void generateKey() throws Exception {
		ed25519KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
	}

	@Test
	public void encryptWithEd25519CurveIsRejected() {
		try {
			ecCryptomanagerService.asymmetricEcEncrypt(ed25519KeyPair.getPublic(), DATA, "Ed25519");
			fail("Ed25519 key must be rejected");
		} catch (CryptoManagerSerivceException ex) {
			assertError(ex);
		}
	}

	@Test
	public void encryptWithEdDsaCurveNameIsRejected() {
		try {
			ecCryptomanagerService.asymmetricEcEncrypt(ed25519KeyPair.getPublic(), DATA, null, null, "EdDSA");
			fail("Ed25519 key must be rejected");
		} catch (CryptoManagerSerivceException ex) {
			assertError(ex);
		}
	}

	@Test
	public void encryptWithEd25519KeyIsRejectedEvenWithoutCurveName() {
		try {
			ecCryptomanagerService.asymmetricEcEncrypt(ed25519KeyPair.getPublic(), DATA, null, null, null);
			fail("Ed25519 key must be rejected");
		} catch (CryptoManagerSerivceException ex) {
			assertError(ex);
		}
	}

	@Test
	public void decryptWithEd25519KeyIsRejected() {
		try {
			ecCryptomanagerService.asymmetricEcDecrypt(ed25519KeyPair.getPrivate(), DATA, null, "Ed25519");
			fail("Ed25519 key must be rejected");
		} catch (CryptoManagerSerivceException ex) {
			assertError(ex);
		}
	}

	private static void assertError(CryptoManagerSerivceException ex) {
		assertEquals(CryptomanagerErrorCode.EC_SIGN_KEY_ENCRYPTION_NOT_SUPPORTED.getErrorCode(), ex.getErrorCode());
		assertEquals(EXPECTED_MESSAGE, ex.getErrorText());
	}
}
