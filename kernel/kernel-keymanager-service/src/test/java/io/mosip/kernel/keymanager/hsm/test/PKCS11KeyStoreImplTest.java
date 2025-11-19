package io.mosip.kernel.keymanager.hsm.test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import io.mosip.kernel.core.keymanager.exception.KeystoreProcessingException;
import io.mosip.kernel.core.keymanager.exception.NoSuchSecurityProviderException;
import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.keymanager.hsm.constant.KeymanagerConstant;
import io.mosip.kernel.keymanager.hsm.impl.pkcs.PKCS11KeyStoreImpl;
import io.mosip.kernel.keymanager.hsm.util.CertificateUtility;

/**
 * Unit tests for {@link PKCS11KeyStoreImpl}.
 */
public class PKCS11KeyStoreImplTest {

	private static final String RSA_ALIAS = "rsa-key";
	private static final String RSA_CHILD_ALIAS = "rsa-child-key";
	private static final String EC_ALIAS = "ec-key";
	private static final String SYM_ALIAS = "sym-key";

	private PKCS11KeyStoreImpl pkcs11KeyStore;
	private CertificateParameters certificateParameters;
	private String previousKeystoreTypeProp;
	private String previousConfigPathProp;

	@Before
	public void setUp() throws Exception {
		Security.removeProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
		Security.addProvider(new TestProvider());

		previousKeystoreTypeProp = System.getProperty("mosip.kernel.keymanager.hsm.keystore-type");
		previousConfigPathProp = System.getProperty("mosip.kernel.keymanager.hsm.config-path");
		System.setProperty("mosip.kernel.keymanager.hsm.keystore-type", "PKCS11");
		System.setProperty("mosip.kernel.keymanager.hsm.config-path", "/test/pkcs11/config");

		pkcs11KeyStore = new PKCS11KeyStoreImpl(buildParams("changeit", true));
		certificateParameters = new CertificateParameters("commonName", "organizationalUnit", "organization", "location",
				"state", "country", LocalDateTime.now(), LocalDateTime.now().plusDays(30));
	}

	@After
	public void tearDown() {
		Security.removeProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
		restoreSystemProperty("mosip.kernel.keymanager.hsm.keystore-type", previousKeystoreTypeProp);
		restoreSystemProperty("mosip.kernel.keymanager.hsm.config-path", previousConfigPathProp);
	}

	private void restoreSystemProperty(String key, String previousValue) {
		if (previousValue == null) {
			System.clearProperty(key);
		} else {
			System.setProperty(key, previousValue);
		}
	}

	@Test
	public void shouldGenerateAndReadAsymmetricKey() {
		generateSelfSignedCertificate(RSA_ALIAS);

		PrivateKeyEntry entry = pkcs11KeyStore.getAsymmetricKey(RSA_ALIAS);
		assertNotNull(entry);
		assertNotNull(pkcs11KeyStore.getPrivateKey(RSA_ALIAS));
		assertNotNull(pkcs11KeyStore.getPublicKey(RSA_ALIAS));
		assertNotNull(pkcs11KeyStore.getCertificate(RSA_ALIAS));

		PrivateKeyEntry cachedEntry = pkcs11KeyStore.getAsymmetricKey(RSA_ALIAS);
		assertThat(cachedEntry, sameInstance(entry));
	}

	@Test
	public void shouldGenerateChildCertificateUsingSignerAlias() {
		try (MockedStatic<CertificateUtility> certificateMock = Mockito.mockStatic(CertificateUtility.class)) {
			X509Certificate leafCertificate = createMockCertificate();
			X509Certificate childCertificate = createMockCertificate();
			certificateMock
					.when(() -> CertificateUtility.generateX509Certificate(Mockito.any(PrivateKey.class),
							Mockito.any(PublicKey.class), Mockito.any(CertificateParameters.class), Mockito.any(),
							Mockito.anyString(), Mockito.anyString()))
					.thenReturn(leafCertificate, childCertificate);

			pkcs11KeyStore.generateAndStoreAsymmetricKey(RSA_ALIAS, null, certificateParameters);
			pkcs11KeyStore.generateAndStoreAsymmetricKey(RSA_CHILD_ALIAS, RSA_ALIAS, certificateParameters);
		}

		assertNotNull(pkcs11KeyStore.getCertificate(RSA_CHILD_ALIAS));
	}

	@Test
	public void shouldGenerateEcKeyWhenCurveProvided() {
		generateSelfSignedCertificate(RSA_ALIAS);

		try (MockedStatic<CertificateUtility> certificateMock = Mockito.mockStatic(CertificateUtility.class)) {
			X509Certificate certificate = createMockCertificate("EC");
			certificateMock
					.when(() -> CertificateUtility.generateX509Certificate(Mockito.any(PrivateKey.class),
							Mockito.any(PublicKey.class), Mockito.any(CertificateParameters.class), Mockito.any(),
							Mockito.anyString(), Mockito.anyString()))
					.thenReturn(certificate);
			pkcs11KeyStore.generateAndStoreAsymmetricKey(EC_ALIAS, RSA_ALIAS, certificateParameters, "secp256r1");
		}

		assertNotNull(pkcs11KeyStore.getCertificate(EC_ALIAS));
	}

	@Test
	public void shouldGenerateAndReadSymmetricKey() {
		pkcs11KeyStore.generateAndStoreSymmetricKey(SYM_ALIAS);

		SecretKey secretKey = pkcs11KeyStore.getSymmetricKey(SYM_ALIAS);
		assertNotNull(secretKey);

		SecretKey cached = pkcs11KeyStore.getSymmetricKey(SYM_ALIAS);
		assertThat(cached, sameInstance(secretKey));
	}

	@Test
	public void shouldReturnAllAliases() {
		generateSelfSignedCertificate(RSA_ALIAS);
		pkcs11KeyStore.generateAndStoreSymmetricKey(SYM_ALIAS);

		List<String> aliases = pkcs11KeyStore.getAllAlias();
		assertTrue(aliases.contains(RSA_ALIAS));
		assertTrue(aliases.contains(SYM_ALIAS));
	}

	@Test
	public void shouldDeleteKeys() throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
		generateSelfSignedCertificate(RSA_ALIAS);
		pkcs11KeyStore.generateAndStoreSymmetricKey(SYM_ALIAS);

		pkcs11KeyStore.deleteKey(RSA_ALIAS);
		pkcs11KeyStore.deleteKey(SYM_ALIAS);

		assertNull(pkcs11KeyStore.getKey(RSA_ALIAS));
		assertNull(pkcs11KeyStore.getKey(SYM_ALIAS));
	}

	@Test(expected = NoSuchSecurityProviderException.class)
	public void shouldThrowWhenAsymmetricAliasMissing() {
		pkcs11KeyStore.getAsymmetricKey("missing");
	}

	@Test(expected = NoSuchSecurityProviderException.class)
	public void shouldThrowWhenSymmetricAliasMissing() {
		pkcs11KeyStore.getSymmetricKey("missing");
	}

	@Test(expected = KeystoreProcessingException.class)
	public void shouldRejectEd25519Curve() {
		pkcs11KeyStore.generateAndStoreAsymmetricKey("ed25519-key", null, certificateParameters,
				KeymanagerConstant.ED25519_KEY_TYPE);
	}

	@Test
	public void shouldStoreExternalCertificate() {
		generateSelfSignedCertificate(RSA_ALIAS);
		PrivateKey privateKey = pkcs11KeyStore.getPrivateKey(RSA_ALIAS);
		X509Certificate certificate = pkcs11KeyStore.getCertificate(RSA_ALIAS);

		pkcs11KeyStore.storeCertificate("manualAlias", privateKey, certificate);

		assertThat(pkcs11KeyStore.getCertificate("manualAlias"), is(certificate));
	}

	@Test
	public void shouldProvideProviderName() {
		String providerName = pkcs11KeyStore.getKeystoreProviderName();
		assertThat(providerName, containsString(KeymanagerConstant.SUN_PKCS11_PROVIDER));
	}

	@Test(expected = KeystoreProcessingException.class)
	public void shouldFailWhenKeyStoreMissing() {
		ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", null);
		pkcs11KeyStore.getKeystoreProviderName();
	}

	@Test
	public void shouldReloadProviderAfterInterval() {
		ReflectionTestUtils.setField(pkcs11KeyStore, "lastProviderLoadedTime", LocalDateTime.now().minusSeconds(120));
		ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "reloadProvider");

		assertThat(pkcs11KeyStore.getKeystoreProviderName(), is(KeymanagerConstant.SUN_PKCS11_PROVIDER));
	}

	@Test
	public void shouldSkipReloadWithinInterval() {
		Provider existingProvider = (Provider) ReflectionTestUtils.getField(pkcs11KeyStore, "provider");
		ReflectionTestUtils.setField(pkcs11KeyStore, "lastProviderLoadedTime", LocalDateTime.now());
		ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "reloadProvider");

		Provider latestProvider = (Provider) ReflectionTestUtils.getField(pkcs11KeyStore, "provider");
		assertThat(latestProvider, sameInstance(existingProvider));
	}

	@Test
	public void shouldExposeRawKeyAccess() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
		generateSelfSignedCertificate(RSA_ALIAS);

		Key key = pkcs11KeyStore.getKey(RSA_ALIAS);
		assertNotNull(key);
	}

	@Test
	public void shouldReturnNullPasswordWhenKeystorePasswordBlank() throws Exception {
		PKCS11KeyStoreImpl blankPasswordKeystore = new PKCS11KeyStoreImpl(buildParams("   ", true));
		Object passwordProtection = ReflectionTestUtils.invokeMethod(blankPasswordKeystore, "getPasswordProtection");
		assertNull(passwordProtection);
	}

	@Test
	public void shouldCachePrivateKeysWhenEnabled() {
		generateSelfSignedCertificate(RSA_ALIAS);
		pkcs11KeyStore.getAsymmetricKey(RSA_ALIAS);
		@SuppressWarnings("unchecked")
		Map<String, PrivateKeyEntry> cache = (Map<String, PrivateKeyEntry>) ReflectionTestUtils
				.getField(pkcs11KeyStore, "privateKeyReferenceCache");
		assertNotNull(cache.get(RSA_ALIAS));
	}

	@Test
	public void shouldCacheSecretKeysWhenEnabled() {
		pkcs11KeyStore.generateAndStoreSymmetricKey(SYM_ALIAS);
		SecretKey secretKey = pkcs11KeyStore.getSymmetricKey(SYM_ALIAS);
		@SuppressWarnings("unchecked")
		Map<String, SecretKey> cache = (Map<String, SecretKey>) ReflectionTestUtils.getField(pkcs11KeyStore,
				"secretKeyReferenceCache");
		assertThat(cache.get(SYM_ALIAS), sameInstance(secretKey));
	}

	@Test
	public void shouldDisableKeyReferenceCacheWhenFlagFalse() throws Exception {
		PKCS11KeyStoreImpl cacheDisabledStore = new PKCS11KeyStoreImpl(buildParams("changeit", false));
		generateSelfSignedCertificate(cacheDisabledStore, "nocache-alias");
		cacheDisabledStore.getAsymmetricKey("nocache-alias");
		assertNull(ReflectionTestUtils.getField(cacheDisabledStore, "privateKeyReferenceCache"));
		assertNull(ReflectionTestUtils.getField(cacheDisabledStore, "secretKeyReferenceCache"));
	}

	@Test(expected = KeystoreProcessingException.class)
	public void shouldThrowWhenEdCurveRequested() {
		pkcs11KeyStore.generateAndStoreAsymmetricKey("ed-alias", null, certificateParameters,
				KeymanagerConstant.ED25519_KEY_TYPE);
	}

	@Test
	public void shouldUseDefaultSecureRandomWhenProviderLacksService() throws Exception {
		Provider existingProvider = Security.getProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
		Security.removeProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
		Security.addProvider(new NoSecureRandomProvider());
		try {
			PKCS11KeyStoreImpl store = new PKCS11KeyStoreImpl(buildParams("changeit", true));
			SecureRandom secureRandom = (SecureRandom) ReflectionTestUtils.getField(store, "secureRandom");
			assertNotNull(secureRandom);
			assertThat(secureRandom.getAlgorithm(), not(KeymanagerConstant.KEYSTORE_TYPE_PKCS11));
		} finally {
			Security.removeProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
			if (existingProvider != null) {
				Security.addProvider(existingProvider);
			} else {
				Security.addProvider(new TestProvider());
			}
		}
	}

	@Test(expected = NoSuchSecurityProviderException.class)
	public void shouldThrowWhenProviderUnavailableDuringSetup() {
		Provider existingProvider = Security.getProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
		Security.removeProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
		try {
			ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "setupProvider", "/tmp/config");
		} finally {
			Security.removeProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
			if (existingProvider != null) {
				Security.addProvider(existingProvider);
			} else {
				Security.addProvider(new TestProvider());
			}
		}
	}

	@Test(expected = NoSuchSecurityProviderException.class)
	public void shouldThrowWhenProviderConfigurationInvalid() {
		Provider existingProvider = Security.getProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
		Security.removeProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
		Security.addProvider(new FaultyProvider());
		try {
			ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "setupProvider", "/invalid/config");
		} finally {
			Security.removeProvider(KeymanagerConstant.SUN_PKCS11_PROVIDER);
			if (existingProvider != null) {
				Security.addProvider(existingProvider);
			} else {
				Security.addProvider(new TestProvider());
			}
		}
	}

	@Test(expected = NoSuchSecurityProviderException.class)
	public void shouldThrowWhenAddProviderFails() {
		Provider provider = new TestProvider();
		try (MockedStatic<Security> securityMock = Mockito.mockStatic(Security.class)) {
			securityMock.when(() -> Security.removeProvider(provider.getName())).thenAnswer(invocation -> null);
			securityMock.when(() -> Security.addProvider(provider)).thenReturn(-1);
			ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "addProvider", provider);
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void shouldWrapKeystoreInstanceErrors() throws Exception {
		try (MockedStatic<KeyStore> keyStoreStatic = Mockito.mockStatic(KeyStore.class)) {
			keyStoreStatic.when(() -> KeyStore.getInstance(Mockito.anyString(), Mockito.any(Provider.class)))
					.thenThrow(new KeyStoreException("boom"));
			ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "getKeystoreInstance", "PKCS11", new TestProvider());
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void shouldWrapAliasEnumerationErrors() throws Exception {
		KeyStore original = (KeyStore) ReflectionTestUtils.getField(pkcs11KeyStore, "keyStore");
		KeyStore failingKeyStore = Mockito.mock(KeyStore.class);
		Mockito.when(failingKeyStore.aliases()).thenThrow(new KeyStoreException("boom"));
		ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", failingKeyStore);
		try {
			pkcs11KeyStore.getAllAlias();
		} finally {
			ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", original);
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void shouldWrapKeyRetrievalErrors() throws Exception {
		KeyStore original = (KeyStore) ReflectionTestUtils.getField(pkcs11KeyStore, "keyStore");
		KeyStore failingKeyStore = Mockito.mock(KeyStore.class);
		Mockito.when(failingKeyStore.getKey(Mockito.anyString(), Mockito.any(char[].class)))
				.thenThrow(new KeyStoreException("boom"));
		ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", failingKeyStore);
		try {
			pkcs11KeyStore.getKey("any");
		} finally {
			ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", original);
		}
	}

	@Test
	public void shouldWrapInternalStoreCertificateErrors() throws Exception {
		KeyStore original = (KeyStore) ReflectionTestUtils.getField(pkcs11KeyStore, "keyStore");
		KeyStore failingKeyStore = Mockito.mock(KeyStore.class);
		Mockito.doThrow(new KeyStoreException("boom")).when(failingKeyStore).setEntry(Mockito.anyString(),
				Mockito.any(PrivateKeyEntry.class), Mockito.any(ProtectionParameter.class));
		ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", failingKeyStore);
		try {
			PrivateKey privateKey = Mockito.mock(PrivateKey.class);
			Mockito.when(privateKey.getAlgorithm()).thenReturn("RSA");
			X509Certificate certificate = createMockCertificate();
			try {
				ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "storeCertificate", "alias",
						new Certificate[] { certificate }, privateKey);
				org.junit.Assert.fail("Expected KeystoreProcessingException");
			} catch (KeystoreProcessingException expected) {
				// expected path
			}
		} finally {
			ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", original);
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void shouldWrapSymmetricStoreErrors() throws Exception {
		KeyStore original = (KeyStore) ReflectionTestUtils.getField(pkcs11KeyStore, "keyStore");
		KeyStore failingKeyStore = Mockito.mock(KeyStore.class);
		Mockito.doThrow(new KeyStoreException("boom")).when(failingKeyStore).setEntry(Mockito.anyString(),
				Mockito.any(SecretKeyEntry.class), Mockito.any(ProtectionParameter.class));
		ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", failingKeyStore);
		try {
			pkcs11KeyStore.generateAndStoreSymmetricKey("failure-alias");
		} finally {
			ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", original);
		}
	}

	@Test
	public void shouldWrapExternalStoreCertificateErrors() throws Exception {
		KeyStore original = (KeyStore) ReflectionTestUtils.getField(pkcs11KeyStore, "keyStore");
		KeyStore failingKeyStore = Mockito.mock(KeyStore.class);
		Mockito.doThrow(new KeyStoreException("boom")).when(failingKeyStore).setEntry(Mockito.anyString(),
				Mockito.any(PrivateKeyEntry.class), Mockito.any(ProtectionParameter.class));
		ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", failingKeyStore);
		try {
			PrivateKey privateKey = Mockito.mock(PrivateKey.class);
			Mockito.when(privateKey.getAlgorithm()).thenReturn("RSA");
			X509Certificate certificate = createMockCertificate();
			try {
				pkcs11KeyStore.storeCertificate("external-alias", privateKey, certificate);
				org.junit.Assert.fail("Expected KeystoreProcessingException");
			} catch (KeystoreProcessingException expected) {
				// expected path
			}
		} finally {
			ReflectionTestUtils.setField(pkcs11KeyStore, "keyStore", original);
		}
	}

	@Test(expected = io.mosip.kernel.core.exception.NoSuchAlgorithmException.class)
	public void shouldPropagateRsaKeyGenerationErrors() throws Exception {
		try (MockedStatic<KeyPairGenerator> keyPairGeneratorStatic = Mockito.mockStatic(KeyPairGenerator.class)) {
			keyPairGeneratorStatic
					.when(() -> KeyPairGenerator.getInstance(Mockito.anyString(), Mockito.any(Provider.class)))
					.thenThrow(new java.security.NoSuchAlgorithmException("boom"));
			ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "generateRSAKeyPair");
		}
	}

	@Test(expected = io.mosip.kernel.core.exception.NoSuchAlgorithmException.class)
	public void shouldPropagateEcKeyGenerationErrors() throws Exception {
		try (MockedStatic<KeyPairGenerator> keyPairGeneratorStatic = Mockito.mockStatic(KeyPairGenerator.class)) {
			keyPairGeneratorStatic
					.when(() -> KeyPairGenerator.getInstance(Mockito.anyString(), Mockito.any(Provider.class)))
					.thenThrow(new java.security.NoSuchAlgorithmException("boom"));
			ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "generateECKeyPair", "secp256r1");
		}
	}

	@Test(expected = io.mosip.kernel.core.exception.NoSuchAlgorithmException.class)
	public void shouldPropagateSymmetricKeyGenerationErrors() throws Exception {
		try (MockedStatic<KeyGenerator> keyGeneratorStatic = Mockito.mockStatic(KeyGenerator.class)) {
			keyGeneratorStatic.when(() -> KeyGenerator.getInstance(Mockito.anyString(), Mockito.any(Provider.class)))
					.thenThrow(new java.security.NoSuchAlgorithmException("boom"));
			ReflectionTestUtils.invokeMethod(pkcs11KeyStore, "generateSymmetricKey");
		}
	}

	private void generateSelfSignedCertificate(String alias) {
		generateSelfSignedCertificate(pkcs11KeyStore, alias);
	}

	private void generateSelfSignedCertificate(PKCS11KeyStoreImpl store, String alias) {
		try (MockedStatic<CertificateUtility> certificateMock = Mockito.mockStatic(CertificateUtility.class)) {
			X509Certificate certificate = createMockCertificate();
			certificateMock
					.when(() -> CertificateUtility.generateX509Certificate(Mockito.any(PrivateKey.class),
							Mockito.any(PublicKey.class), Mockito.any(CertificateParameters.class), Mockito.any(),
							Mockito.anyString(), Mockito.anyString()))
					.thenReturn(certificate);
			store.generateAndStoreAsymmetricKey(alias, null, certificateParameters);
		}
	}

	private X509Certificate createMockCertificate() {
		return createMockCertificate(KeymanagerConstant.RSA_KEY_TYPE);
	}

	private X509Certificate createMockCertificate(String algorithm) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
			if (KeymanagerConstant.RSA_KEY_TYPE.equalsIgnoreCase(algorithm)) {
				generator.initialize(2048);
			} else if ("EC".equalsIgnoreCase(algorithm)) {
				generator.initialize(new ECGenParameterSpec("secp256r1"));
			}
			KeyPair keyPair = generator.generateKeyPair();
			X509Certificate certificate = Mockito.mock(X509Certificate.class);
			Mockito.when(certificate.getPublicKey()).thenReturn(keyPair.getPublic());
			X500Principal principal = new X500Principal("CN=Test");
			Mockito.when(certificate.getSubjectX500Principal()).thenReturn(principal);
			Mockito.when(certificate.getIssuerX500Principal()).thenReturn(principal);
			return certificate;
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new IllegalStateException(e);
		}
	}

	private Map<String, String> buildParams(String password, boolean enableCache) {
		Map<String, String> params = new HashMap<>();
		params.put("mosip.kernel.keymanager.hsm.keystore-type", "PKCS11");
		params.put("mosip.kernel.keymanager.hsm.config-path", "/test/pkcs11/config");
		params.put(KeymanagerConstant.CONFIG_FILE_PATH, "./src/test/resources/keystore/pkcs11.cfg");
		params.put(KeymanagerConstant.PKCS11_KEYSTORE_PASSWORD, password);
		params.put(KeymanagerConstant.SYM_KEY_ALGORITHM, "AES");
		params.put(KeymanagerConstant.SYM_KEY_SIZE, "256");
		params.put(KeymanagerConstant.ASYM_KEY_ALGORITHM, KeymanagerConstant.RSA_KEY_TYPE);
		params.put(KeymanagerConstant.ASYM_KEY_SIZE, "2048");
		params.put(KeymanagerConstant.CERT_SIGN_ALGORITHM, "SHA256withRSA");
		params.put(KeymanagerConstant.FLAG_KEY_REF_CACHE, Boolean.toString(enableCache));
		params.put(KeymanagerConstant.ASYM_KEY_EC_ALGORITHM, "EC");
		return params;
	}

	@SuppressWarnings("deprecation")
	public static class TestProvider extends Provider {
		private static final long serialVersionUID = 1L;

		public TestProvider() {
			super(KeymanagerConstant.SUN_PKCS11_PROVIDER, 1.0, "Test PKCS11 provider");
			putService(new Provider.Service(this, "KeyStore", KeymanagerConstant.KEYSTORE_TYPE_PKCS11,
					TestKeyStoreSpi.class.getName(), null, null));
			putService(new Provider.Service(this, "KeyPairGenerator", "RSA",
					TestRSAKeyPairGeneratorSpi.class.getName(), null, null));
			putService(new Provider.Service(this, "KeyPairGenerator", "EC",
					TestECKeyPairGeneratorSpi.class.getName(), null, null));
			putService(new Provider.Service(this, "KeyGenerator", "AES",
					TestAesKeyGeneratorSpi.class.getName(), null, null));
			putService(new Provider.Service(this, "SecureRandom", KeymanagerConstant.KEYSTORE_TYPE_PKCS11,
					TestSecureRandomSpi.class.getName(), null, null));
		}

		@Override
		public Provider configure(String configArg) {
			return this;
		}
	}

	@SuppressWarnings("deprecation")
	public static class NoSecureRandomProvider extends Provider {
		private static final long serialVersionUID = 1L;

		public NoSecureRandomProvider() {
			super(KeymanagerConstant.SUN_PKCS11_PROVIDER, 1.0, "Test PKCS11 provider without SecureRandom");
			putService(new Provider.Service(this, "KeyStore", KeymanagerConstant.KEYSTORE_TYPE_PKCS11,
					TestKeyStoreSpi.class.getName(), null, null));
			putService(new Provider.Service(this, "KeyPairGenerator", "RSA",
					TestRSAKeyPairGeneratorSpi.class.getName(), null, null));
			putService(new Provider.Service(this, "KeyPairGenerator", "EC",
					TestECKeyPairGeneratorSpi.class.getName(), null, null));
			putService(new Provider.Service(this, "KeyGenerator", "AES",
					TestAesKeyGeneratorSpi.class.getName(), null, null));
		}

		@Override
		public Provider configure(String configArg) {
			return this;
		}
	}

	@SuppressWarnings("deprecation")
	public static class FaultyProvider extends Provider {
		private static final long serialVersionUID = 1L;

		public FaultyProvider() {
			super(KeymanagerConstant.SUN_PKCS11_PROVIDER, 1.0, "Faulty PKCS11 provider");
		}

		@Override
		public Provider configure(String configArg) {
			throw new InvalidParameterException("invalid config");
		}
	}

	public static class TestKeyStoreSpi extends KeyStoreSpi {
		private final Map<String, Entry> entries = new ConcurrentHashMap<>();
		private final Map<String, Date> creationDates = new ConcurrentHashMap<>();

		@Override
		public Key engineGetKey(String alias, char[] password)
				throws NoSuchAlgorithmException, UnrecoverableKeyException {
			Entry entry = entries.get(alias);
			if (entry instanceof PrivateKeyEntry privateKeyEntry) {
				return privateKeyEntry.getPrivateKey();
			}
			if (entry instanceof SecretKeyEntry secretKeyEntry) {
				return secretKeyEntry.getSecretKey();
			}
			return null;
		}

		@Override
		public Certificate[] engineGetCertificateChain(String alias) {
			Entry entry = entries.get(alias);
			if (entry instanceof PrivateKeyEntry privateKeyEntry) {
				return privateKeyEntry.getCertificateChain();
			}
			return null;
		}

		@Override
		public Certificate engineGetCertificate(String alias) {
			Entry entry = entries.get(alias);
			if (entry instanceof PrivateKeyEntry privateKeyEntry) {
				Certificate[] chain = privateKeyEntry.getCertificateChain();
				return chain.length > 0 ? chain[0] : null;
			}
			if (entry instanceof TrustedCertificateEntry trustedCertificateEntry) {
				return trustedCertificateEntry.getTrustedCertificate();
			}
			return null;
		}

		@Override
		public Date engineGetCreationDate(String alias) {
			return creationDates.getOrDefault(alias, new Date());
		}

		@Override
		public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
				throws KeyStoreException {
			if (!(key instanceof PrivateKey)) {
				throw new KeyStoreException("Only PrivateKey supported");
			}
			engineSetEntry(alias, new PrivateKeyEntry((PrivateKey) key, chain), null);
		}

		@Override
		public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
			throw new KeyStoreException("Unsupported");
		}

		@Override
		public void engineSetCertificateEntry(String alias, Certificate cert) {
			engineSetEntry(alias, new TrustedCertificateEntry(cert), null);
		}

		@Override
		public void engineDeleteEntry(String alias) {
			entries.remove(alias);
			creationDates.remove(alias);
		}

		@Override
		public Enumeration<String> engineAliases() {
			return Collections.enumeration(new ArrayList<>(entries.keySet()));
		}

		@Override
		public boolean engineContainsAlias(String alias) {
			return entries.containsKey(alias);
		}

		@Override
		public int engineSize() {
			return entries.size();
		}

		@Override
		public boolean engineIsKeyEntry(String alias) {
			Entry entry = entries.get(alias);
			return entry instanceof PrivateKeyEntry || entry instanceof SecretKeyEntry;
		}

		@Override
		public boolean engineIsCertificateEntry(String alias) {
			return entries.get(alias) instanceof TrustedCertificateEntry;
		}

		@Override
		public String engineGetCertificateAlias(Certificate cert) {
			return entries.entrySet().stream().filter(e -> {
				Entry entry = e.getValue();
				if (entry instanceof PrivateKeyEntry privateKeyEntry) {
					return Arrays.asList(privateKeyEntry.getCertificateChain()).contains(cert);
				}
				if (entry instanceof TrustedCertificateEntry trustedCertificateEntry) {
					return trustedCertificateEntry.getTrustedCertificate().equals(cert);
				}
				return false;
			}).map(Map.Entry::getKey).findFirst().orElse(null);
		}

		@Override
		public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
				CertificateException {
			// in-memory store - nothing to persist
		}

		@Override
		public void engineLoad(InputStream stream, char[] password)
				throws IOException, NoSuchAlgorithmException, CertificateException {
			entries.clear();
			creationDates.clear();
		}

		@Override
		public Entry engineGetEntry(String alias, ProtectionParameter protParam)
				throws NoSuchAlgorithmException, UnrecoverableEntryException {
			return entries.get(alias);
		}

		@Override
		public void engineSetEntry(String alias, Entry entry, ProtectionParameter protParam) {
			entries.put(alias, entry);
			creationDates.put(alias, new Date());
		}

		@Override
		public boolean engineEntryInstanceOf(String alias, Class<? extends Entry> entryClass) {
			Entry entry = entries.get(alias);
			return entry != null && entryClass.isInstance(entry);
		}
	}

	public static class TestRSAKeyPairGeneratorSpi extends java.security.KeyPairGeneratorSpi {
		private final KeyPairGenerator delegate;

		public TestRSAKeyPairGeneratorSpi() {
			try {
				this.delegate = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			}
		}

		@Override
		public KeyPair generateKeyPair() {
			return delegate.generateKeyPair();
		}

		@Override
		public void initialize(int keysize, SecureRandom random) {
			delegate.initialize(keysize, random);
		}

		@Override
		public void initialize(AlgorithmParameterSpec params, SecureRandom random)
				throws InvalidAlgorithmParameterException {
			delegate.initialize(params, random);
		}
	}

	public static class TestECKeyPairGeneratorSpi extends java.security.KeyPairGeneratorSpi {
		private final KeyPairGenerator delegate;

		public TestECKeyPairGeneratorSpi() {
			try {
				this.delegate = KeyPairGenerator.getInstance("EC");
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			}
		}

		@Override
		public KeyPair generateKeyPair() {
			return delegate.generateKeyPair();
		}

		@Override
		public void initialize(int keysize, SecureRandom random) {
			// default to commonly supported curve
			try {
				delegate.initialize(new ECGenParameterSpec("secp256r1"), random);
			} catch (InvalidAlgorithmParameterException e) {
				throw new IllegalStateException(e);
			}
		}

		@Override
		public void initialize(AlgorithmParameterSpec params, SecureRandom random)
				throws InvalidAlgorithmParameterException {
			delegate.initialize(params, random);
		}
	}

	public static class TestAesKeyGeneratorSpi extends KeyGeneratorSpi {
		private final javax.crypto.KeyGenerator delegate;

		public TestAesKeyGeneratorSpi() {
			try {
				this.delegate = javax.crypto.KeyGenerator.getInstance("AES");
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			}
		}

		@Override
		protected void engineInit(SecureRandom random) {
			delegate.init(256, random);
		}

		@Override
		protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
				throws InvalidAlgorithmParameterException {
			delegate.init(params, random);
		}

		@Override
		protected void engineInit(int keysize, SecureRandom random) {
			delegate.init(keysize, random);
		}

		@Override
		protected SecretKey engineGenerateKey() {
			return delegate.generateKey();
		}
	}

	public static class TestSecureRandomSpi extends SecureRandomSpi {
		private static final long serialVersionUID = 1L;
		private final SecureRandom delegate = new SecureRandom();

		@Override
		protected void engineSetSeed(byte[] seed) {
			delegate.setSeed(seed);
		}

		@Override
		protected void engineNextBytes(byte[] bytes) {
			delegate.nextBytes(bytes);
		}

		@Override
		protected byte[] engineGenerateSeed(int numBytes) {
			return delegate.generateSeed(numBytes);
		}
	}
}

