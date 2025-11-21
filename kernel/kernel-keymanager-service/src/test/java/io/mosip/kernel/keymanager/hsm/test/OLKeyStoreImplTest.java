package io.mosip.kernel.keymanager.hsm.test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.security.Key;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.core.keymanager.exception.KeystoreProcessingException;
import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.keymanager.hsm.constant.KeymanagerConstant;
import io.mosip.kernel.keymanager.hsm.constant.KeymanagerErrorCode;
import io.mosip.kernel.keymanager.hsm.impl.offline.OLKeyStoreImpl;

/**
 * Test class for OLKeyStoreImpl
 * 
 * @author Test Author
 * @since 1.1.4
 */
@RunWith(SpringRunner.class)
public class OLKeyStoreImplTest {

	private OLKeyStoreImpl olKeyStoreImpl;

	@Mock
	private CertificateParameters certificateParameters;

	@Mock
	private PrivateKey privateKey;

	@Mock
	private Certificate certificate;

	@Before
	public void setUp() throws Exception {
		Map<String, String> params = new HashMap<>();
		params.put("TEST_KEY", "TEST_VALUE");
		olKeyStoreImpl = new OLKeyStoreImpl(params);
	}

	@Test
	public void testConstructorWithParams() throws Exception {
		Map<String, String> params = new HashMap<>();
		params.put("KEY1", "VALUE1");
		params.put("KEY2", "VALUE2");
		OLKeyStoreImpl instance = new OLKeyStoreImpl(params);
		assertThat(instance, is(instance));
	}

	@Test
	public void testConstructorWithNullParams() throws Exception {
		OLKeyStoreImpl instance = new OLKeyStoreImpl(null);
		assertThat(instance, is(instance));
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGetAllAlias() {
		olKeyStoreImpl.getAllAlias();
	}

	@Test
	public void testGetAllAliasExceptionDetails() {
		try {
			olKeyStoreImpl.getAllAlias();
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGetKey() {
		olKeyStoreImpl.getKey("testAlias");
	}

	@Test
	public void testGetKeyExceptionDetails() {
		try {
			olKeyStoreImpl.getKey("testAlias");
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGetAsymmetricKey() {
		olKeyStoreImpl.getAsymmetricKey("testAlias");
	}

	@Test
	public void testGetAsymmetricKeyExceptionDetails() {
		try {
			olKeyStoreImpl.getAsymmetricKey("testAlias");
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGetPrivateKey() {
		olKeyStoreImpl.getPrivateKey("testAlias");
	}

	@Test
	public void testGetPrivateKeyExceptionDetails() {
		try {
			olKeyStoreImpl.getPrivateKey("testAlias");
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGetPublicKey() {
		olKeyStoreImpl.getPublicKey("testAlias");
	}

	@Test
	public void testGetPublicKeyExceptionDetails() {
		try {
			olKeyStoreImpl.getPublicKey("testAlias");
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGetCertificate() {
		olKeyStoreImpl.getCertificate("testAlias");
	}

	@Test
	public void testGetCertificateExceptionDetails() {
		try {
			olKeyStoreImpl.getCertificate("testAlias");
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGetSymmetricKey() {
		olKeyStoreImpl.getSymmetricKey("testAlias");
	}

	@Test
	public void testGetSymmetricKeyExceptionDetails() {
		try {
			olKeyStoreImpl.getSymmetricKey("testAlias");
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testDeleteKey() {
		olKeyStoreImpl.deleteKey("testAlias");
	}

	@Test
	public void testDeleteKeyExceptionDetails() {
		try {
			olKeyStoreImpl.deleteKey("testAlias");
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGenerateAndStoreAsymmetricKey() {
		olKeyStoreImpl.generateAndStoreAsymmetricKey("testAlias", "signKeyAlias", certificateParameters);
	}

	@Test
	public void testGenerateAndStoreAsymmetricKeyExceptionDetails() {
		try {
			olKeyStoreImpl.generateAndStoreAsymmetricKey("testAlias", "signKeyAlias", certificateParameters);
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGenerateAndStoreAsymmetricKeyWithNullSignKeyAlias() {
		olKeyStoreImpl.generateAndStoreAsymmetricKey("testAlias", null, certificateParameters);
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGenerateAndStoreAsymmetricKeyWithNullCertificateParameters() {
		olKeyStoreImpl.generateAndStoreAsymmetricKey("testAlias", "signKeyAlias", null);
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGenerateAndStoreSymmetricKey() {
		olKeyStoreImpl.generateAndStoreSymmetricKey("testAlias");
	}

	@Test
	public void testGenerateAndStoreSymmetricKeyExceptionDetails() {
		try {
			olKeyStoreImpl.generateAndStoreSymmetricKey("testAlias");
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testStoreCertificate() {
		olKeyStoreImpl.storeCertificate("testAlias", privateKey, certificate);
	}

	@Test
	public void testStoreCertificateExceptionDetails() {
		try {
			olKeyStoreImpl.storeCertificate("testAlias", privateKey, certificate);
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testStoreCertificateWithNullPrivateKey() {
		olKeyStoreImpl.storeCertificate("testAlias", null, certificate);
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testStoreCertificateWithNullCertificate() {
		olKeyStoreImpl.storeCertificate("testAlias", privateKey, null);
	}

	@Test
	public void testGetKeystoreProviderName() {
		String providerName = olKeyStoreImpl.getKeystoreProviderName();
		assertThat(providerName, is(KeymanagerConstant.KEYSTORE_TYPE_OFFLINE));
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGenerateAndStoreAsymmetricKeyWithEcCurve() {
		olKeyStoreImpl.generateAndStoreAsymmetricKey("testAlias", "signKeyAlias", certificateParameters, "P-256");
	}

	@Test
	public void testGenerateAndStoreAsymmetricKeyWithEcCurveExceptionDetails() {
		try {
			olKeyStoreImpl.generateAndStoreAsymmetricKey("testAlias", "signKeyAlias", certificateParameters, "P-256");
			fail("Expected KeystoreProcessingException");
		} catch (KeystoreProcessingException e) {
			assertThat(e.getErrorCode(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorCode()));
			assertThat(e.getErrorText(), is(KeymanagerErrorCode.OFFLINE_KEYSTORE_ACCESS_ERROR.getErrorMessage()));
		}
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGenerateAndStoreAsymmetricKeyWithEcCurveAndNullParams() {
		olKeyStoreImpl.generateAndStoreAsymmetricKey("testAlias", null, null, "P-256");
	}

	@Test(expected = KeystoreProcessingException.class)
	public void testGenerateAndStoreAsymmetricKeyWithEcCurveAndNullCurve() {
		olKeyStoreImpl.generateAndStoreAsymmetricKey("testAlias", "signKeyAlias", certificateParameters, null);
	}

}

