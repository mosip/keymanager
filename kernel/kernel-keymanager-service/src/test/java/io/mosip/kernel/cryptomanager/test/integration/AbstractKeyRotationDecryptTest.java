package io.mosip.kernel.cryptomanager.test.integration;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.cache2k.Cache;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils2;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.kernel.cryptomanager.service.EcCryptomanagerService;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.helper.PrivateKeyDecryptorHelper;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;

/**
 * End-to-end check that data encrypted with a key that has since been rotated or
 * has expired can still be decrypted, because decryption resolves the key by the
 * certificate thumbprint embedded in the payload.
 *
 * Runs against the real services, H2 and the PKCS12 test keystore. Each subclass
 * configures one key algorithm via {@code @TestPropertySource}.
 *
 * Key unique identifiers are derived from app id + ref id + generation DATE, so a
 * second key cannot be generated on the same day. Rotation and expiry are therefore
 * simulated by moving the old key's generation/expiry dates into the past, exactly
 * as if it had been created days ago.
 */
@SpringBootTest(classes = KeymanagerTestBootApplication.class)
@RunWith(SpringRunner.class)
public abstract class AbstractKeyRotationDecryptTest {

	protected static final String APP_ID = "REGISTRATION";
	protected static final String BASE_REF_ID = "ROTATION_TEST";
	private static final byte[] PLAIN_TEXT_1 = "payload encrypted with the OLD key".getBytes(StandardCharsets.UTF_8);
	private static final byte[] PLAIN_TEXT_2 = "payload encrypted with the NEW key".getBytes(StandardCharsets.UTF_8);

	@Autowired
	protected CryptomanagerService cryptomanagerService;

	@Autowired
	protected KeymanagerService keymanagerService;

	@Autowired
	protected KeymanagerDBHelper dbHelper;

	@Autowired
	protected PrivateKeyDecryptorHelper privateKeyDecryptorHelper;

	@Autowired
	protected KeyAliasRepository keyAliasRepository;

	@Autowired
	protected KeyStoreRepository keyStoreRepository;

	@Autowired
	protected CryptomanagerUtils cryptomanagerUtil;

	@Autowired
	protected KeymanagerUtil keymanagerUtil;

	@Autowired
	protected EcCryptomanagerService ecCryptomanagerService;

	@Value("${mosip.kernel.data-key-splitter}")
	private String keySplitter;

	/** Algorithm the encryption certificate must use, e.g. "RSA", "EC", "X25519". */
	protected abstract String expectedEncryptionKeyAlgorithm();

	/** Expected EC curve name of the encryption key, or null when not an EC/XDH key. */
	protected abstract String expectedCurveName();

	/**
	 * Reference id of the HSM-held key used for direct (master key) encryption, or null
	 * when this algorithm has no such flow (RSA master-key payloads use the session key
	 * format and are already covered by the existing session-key tests).
	 */
	protected abstract String hsmEncryptionRefId();

	@Before
	public void setUp() {
		cleanDb();
		generateMasterKey(KeymanagerConstant.ROOT, "", false);
		generateMasterKey(APP_ID, "", false);
	}

	@After
	public void tearDown() {
		cleanDb();
	}

	@Test
	public void decryptWithCurrentKey() {
		String cipher = encrypt(BASE_REF_ID, PLAIN_TEXT_1);
		assertEncryptionKeyAlgorithm(BASE_REF_ID);

		assertArrayEquals(PLAIN_TEXT_1, decrypt(BASE_REF_ID, cipher));
	}

	@Test
	public void decryptAfterKeyRotated() {
		String oldCipher = encrypt(BASE_REF_ID, PLAIN_TEXT_1);
		KeyAlias oldKey = singleKey(APP_ID, BASE_REF_ID);

		ageKey(oldKey, true);
		String newCipher = encrypt(BASE_REF_ID, PLAIN_TEXT_2);

		List<KeyAlias> keys = keyAliasRepository.findByApplicationIdAndReferenceId(APP_ID, BASE_REF_ID);
		assertEquals("rotation must have produced a second key", 2, keys.size());
		KeyAlias newKey = keys.stream().filter(k -> !k.getAlias().equals(oldKey.getAlias())).findFirst().get();
		assertNotEquals("new key must have a different certificate", oldKey.getCertThumbprint(), newKey.getCertThumbprint());
		assertEquals("old key must no longer be current", 1, currentKeys(APP_ID, BASE_REF_ID).size());

		assertArrayEquals("old payload must decrypt with the rotated key", PLAIN_TEXT_1, decrypt(BASE_REF_ID, oldCipher));
		assertArrayEquals("new payload must decrypt with the current key", PLAIN_TEXT_2, decrypt(BASE_REF_ID, newCipher));
	}

	@Test
	public void decryptAfterKeyExpiredWithoutReplacement() {
		String cipher = encrypt(BASE_REF_ID, PLAIN_TEXT_1);
		ageKey(singleKey(APP_ID, BASE_REF_ID), true);

		assertTrue("no current key must exist", currentKeys(APP_ID, BASE_REF_ID).isEmpty());
		assertArrayEquals("payload must decrypt with the expired key", PLAIN_TEXT_1, decrypt(BASE_REF_ID, cipher));
	}

	@Test
	public void decryptAfterHsmKeyRotated() {
		String hsmRefId = hsmEncryptionRefId();
		Assume.assumeTrue("no direct HSM-key encryption flow for this algorithm", hsmRefId != null);

		// get (and generate, if needed) the HSM-held encryption key, encrypt directly to it
		String oldCipher = encryptToHsmKey(hsmRefId, PLAIN_TEXT_1);
		KeyAlias oldKey = singleKey(APP_ID, hsmRefId);

		// rotate: old key moved to the past; the next certificate request generates a new HSM key
		ageKey(oldKey, true);
		String newCipher = encryptToHsmKey(hsmRefId, PLAIN_TEXT_2);
		assertEquals("rotation must have produced a second HSM key", 2,
				keyAliasRepository.findByApplicationIdAndReferenceId(APP_ID, hsmRefId).size());

		assertArrayEquals("old payload must decrypt with the rotated HSM key", PLAIN_TEXT_1, decrypt(hsmRefId, oldCipher));
		assertArrayEquals("new payload must decrypt with the current HSM key", PLAIN_TEXT_2, decrypt(hsmRefId, newCipher));
	}

	/**
	 * Base keys are stored wrapped by the application master key (X25519_ENC_KEY for
	 * Ed25519 setups). Rotate the base key AND every master/wrapping key of the app,
	 * then check both the old payload (old base key unwrapped by the OLD master) and a
	 * new payload (new base key wrapped by the NEW master) decrypt.
	 */
	@Test
	public void decryptAfterMasterAndBaseKeyRotated() {
		String oldCipher = encrypt(BASE_REF_ID, PLAIN_TEXT_1);
		KeyAlias oldBaseKey = singleKey(APP_ID, BASE_REF_ID);
		List<KeyAlias> oldMasterKeys = keyAliasRepository.findByApplicationId(APP_ID).stream()
				.filter(k -> !BASE_REF_ID.equals(k.getReferenceId())).toList();
		assertTrue("app must have at least one master key", !oldMasterKeys.isEmpty());

		ageKey(oldBaseKey, true);
		oldMasterKeys.forEach(k -> ageKey(k, true));

		String newCipher = encrypt(BASE_REF_ID, PLAIN_TEXT_2);
		KeyAlias newBaseKey = keyAliasRepository.findByApplicationIdAndReferenceId(APP_ID, BASE_REF_ID).stream()
				.filter(k -> !k.getAlias().equals(oldBaseKey.getAlias())).findFirst().get();
		String oldMasterAlias = keyStoreRepository.findByAlias(oldBaseKey.getAlias()).get().getMasterAlias();
		String newMasterAlias = keyStoreRepository.findByAlias(newBaseKey.getAlias()).get().getMasterAlias();
		assertNotEquals("new base key must be wrapped by the rotated master key", oldMasterAlias, newMasterAlias);

		assertArrayEquals("old payload must decrypt (old base key, old master)", PLAIN_TEXT_1, decrypt(BASE_REF_ID, oldCipher));
		assertArrayEquals("new payload must decrypt (new base key, new master)", PLAIN_TEXT_2, decrypt(BASE_REF_ID, newCipher));
	}

	// ---------------------------------------------------------------- helpers

	protected String encrypt(String refId, byte[] data) {
		CryptomanagerRequestDto request = request(refId, data);
		return cryptomanagerService.encrypt(request).getData();
	}

	protected byte[] decrypt(String refId, String cipher) {
		clearCaches();
		CryptomanagerRequestDto request = new CryptomanagerRequestDto();
		request.setApplicationId(APP_ID);
		request.setReferenceId(refId);
		request.setTimeStamp(DateUtils2.getUTCCurrentDateTime());
		request.setData(cipher);
		return CryptoUtil.decodeURLSafeBase64(cryptomanagerService.decrypt(request).getData());
	}

	/**
	 * Builds the payload exactly as {@code CryptomanagerServiceImpl.encrypt} does for EC
	 * keys, but against an HSM-held key (the encrypt API refuses master keys; external
	 * clients encrypt to the downloaded certificate directly).
	 */
	private String encryptToHsmKey(String refId, byte[] data) {
		clearCaches();
		Certificate certificate = cryptomanagerUtil.getCertificate(APP_ID, refId);
		PublicKey publicKey = certificate.getPublicKey();
		assertEquals(expectedEncryptionKeyAlgorithm(), normalizeAlgorithm(publicKey.getAlgorithm()));

		byte[] certThumbprint = cryptomanagerUtil.getCertificateThumbprint(certificate);
		byte[] aad = cryptomanagerUtil.generateRandomBytes(io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant.GCM_AAD_LENGTH);
		String curveName = keymanagerUtil.getEcCurveName(publicKey);
		byte[] encryptedData = ecCryptomanagerService.asymmetricEcEncrypt(publicKey, data, null, aad, curveName);
		byte[] encryptedDataWithIv = cryptomanagerUtil.concatByteArrays(aad, encryptedData);
		byte[] headerBytes = cryptomanagerUtil.getHeaderByte(curveName);
		byte[] concatedData = cryptomanagerUtil.concatCertThumbprint(certThumbprint, encryptedDataWithIv);
		return CryptoUtil.encodeToURLSafeBase64(CryptoUtil.combineByteArray(concatedData, headerBytes, keySplitter));
	}

	private CryptomanagerRequestDto request(String refId, byte[] data) {
		clearCaches();
		CryptomanagerRequestDto request = new CryptomanagerRequestDto();
		request.setApplicationId(APP_ID);
		request.setReferenceId(refId);
		request.setTimeStamp(DateUtils2.getUTCCurrentDateTime());
		request.setData(CryptoUtil.encodeToURLSafeBase64(data));
		return request;
	}

	private void assertEncryptionKeyAlgorithm(String refId) {
		Certificate certificate = cryptomanagerUtil.getCertificate(APP_ID, refId);
		PublicKey publicKey = certificate.getPublicKey();
		assertEquals("test is not running with the intended key algorithm", expectedEncryptionKeyAlgorithm(),
				normalizeAlgorithm(publicKey.getAlgorithm()));
		if (expectedCurveName() != null) {
			assertTrue("unexpected curve: " + keymanagerUtil.getEcCurveName(publicKey),
					expectedCurveName().equalsIgnoreCase(keymanagerUtil.getEcCurveName(publicKey)));
		}
	}

	private static String normalizeAlgorithm(String algorithm) {
		if (algorithm.equalsIgnoreCase("ECDSA")) return "EC";
		if (algorithm.equalsIgnoreCase("XDH")) return "X25519";
		return algorithm;
	}

	/** Moves a key into the past so it is no longer current (expired), as if created days ago. */
	protected void ageKey(KeyAlias key, boolean expired) {
		LocalDateTime now = DateUtils2.getUTCCurrentDateTime();
		key.setKeyGenerationTime(now.minusDays(10));
		key.setKeyExpiryTime(expired ? now.minusDays(1) : now.plusDays(1));
		// unique identifier is derived from the generation date; keep it unique like a real older key
		key.setUniqueIdentifier(UUID.randomUUID().toString().replace("-", "").substring(0, 32));
		keyAliasRepository.saveAndFlush(key);
		clearCaches();
	}

	private KeyAlias singleKey(String appId, String refId) {
		List<KeyAlias> keys = keyAliasRepository.findByApplicationIdAndReferenceId(appId, refId);
		assertEquals("expected exactly one key for " + appId + "/" + refId, 1, keys.size());
		return keys.get(0);
	}

	private List<KeyAlias> currentKeys(String appId, String refId) {
		clearCaches();
		Map<String, List<KeyAlias>> map = dbHelper.getKeyAliases(appId, refId, DateUtils2.getUTCCurrentDateTime());
		return map.get(KeymanagerConstant.CURRENTKEYALIAS);
	}

	protected void generateMasterKey(String appId, String refId, boolean force) {
		KeyPairGenerateRequestDto request = new KeyPairGenerateRequestDto();
		request.setApplicationId(appId);
		request.setReferenceId(refId);
		request.setForce(force);
		keymanagerService.generateMasterKey("CERTIFICATE", request);
		clearCaches();
	}

	private void cleanDb() {
		keyStoreRepository.deleteAll();
		keyAliasRepository.deleteAll();
		clearCaches();
	}

	protected void clearCaches() {
		((Cache<?, ?>) ReflectionTestUtils.getField(dbHelper, "keyAliasCache")).clear();
		((Cache<?, ?>) ReflectionTestUtils.getField(privateKeyDecryptorHelper, "cacheDecryptData")).clear();
	}
}
