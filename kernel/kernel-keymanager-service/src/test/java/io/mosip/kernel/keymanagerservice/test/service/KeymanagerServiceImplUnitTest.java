package io.mosip.kernel.keymanagerservice.test.service;

import io.mosip.kernel.core.keymanager.model.CertificateEntry;
import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.util.DateUtils2;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanagerservice.constant.KeyReferenceIdConsts;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.helper.SubjectAlternativeNamesHelper;
import io.mosip.kernel.keymanagerservice.service.impl.KeymanagerServiceImpl;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.core.keymanager.exception.KeystoreProcessingException;
import io.mosip.kernel.core.keymanager.exception.NoSuchSecurityProviderException;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import javax.security.auth.x500.X500Principal;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class KeymanagerServiceImplUnitTest {

    @Mock
    private ECKeyStore keyStore;

    @Mock
    private KeymanagerDBHelper dbHelper;

    @Mock
    private KeymanagerUtil keymanagerUtil;

    @Mock
    private CryptomanagerUtils cryptomanagerUtil;

    @Mock
    private SubjectAlternativeNamesHelper sanHelper;

    @Mock
    private X509Certificate x509Certificate;

    @InjectMocks
    private KeymanagerServiceImpl service;

    private CertificateParameters certificateParameters;

    @Before
    public void setUp() {
        certificateParameters = Mockito.mock(CertificateParameters.class);
        ReflectionTestUtils.setField(service, "ed25519SupportFlag", true);
    }

    @Test
    public void testGetCertificateEntry_WithPrivateKey() {
        String alias = "test-alias";
        PrivateKey privateKey = Mockito.mock(PrivateKey.class);
        X509Certificate[] certChain = new X509Certificate[]{x509Certificate};
        
        PrivateKeyEntry privateKeyEntry = Mockito.mock(PrivateKeyEntry.class);
        when(privateKeyEntry.getCertificateChain()).thenReturn(certChain);
        when(privateKeyEntry.getPrivateKey()).thenReturn(privateKey);
        when(keyStore.getAsymmetricKey(alias)).thenReturn(privateKeyEntry);

        CertificateEntry<X509Certificate, PrivateKey> result = ReflectionTestUtils.invokeMethod(
                service, "getCertificateEntry", alias, true);

        assertNotNull(result);
        assertArrayEquals(certChain, result.getChain());
        assertSame(privateKey, result.getPrivateKey());
    }

    @Test
    public void testGetCertificateEntry_WithoutPrivateKey_FromDB() {
        String alias = "test-alias";
        String certData = "cert-data";
        
        when(keyStore.getAsymmetricKey(alias)).thenThrow(new KeystoreProcessingException("", ""));
        
        io.mosip.kernel.keymanagerservice.entity.KeyStore dbKeyStore = Mockito.mock(io.mosip.kernel.keymanagerservice.entity.KeyStore.class);
        when(dbKeyStore.getCertificateData()).thenReturn(certData);
        when(dbHelper.getKeyStoreFromDB(alias)).thenReturn(Optional.of(dbKeyStore));
        when(keymanagerUtil.convertToCertificate(certData)).thenReturn(x509Certificate);

        CertificateEntry<X509Certificate, PrivateKey> result = ReflectionTestUtils.invokeMethod(
                service, "getCertificateEntry", alias, false);

        assertNotNull(result);
        assertEquals(1, result.getChain().length);
        assertSame(x509Certificate, result.getChain()[0]);
        assertNull(result.getPrivateKey());
    }

    @Test(expected = KeymanagerServiceException.class)
    public void testGetCertificateEntry_CertificateNotFound() {
        String alias = "missing-alias";
        
        when(keyStore.getAsymmetricKey(alias)).thenThrow(new NoSuchSecurityProviderException("", ""));
        when(dbHelper.getKeyStoreFromDB(alias)).thenReturn(Optional.empty());

        ReflectionTestUtils.invokeMethod(service, "getCertificateEntry", alias, false);
    }

    @Test(expected = KeystoreProcessingException.class)
    public void testGetCertificateEntry_PrivateKeyRequired_ThrowsException() {
        String alias = "test-alias";
        
        when(keyStore.getAsymmetricKey(alias)).thenThrow(new KeystoreProcessingException("", ""));

        ReflectionTestUtils.invokeMethod(service, "getCertificateEntry", alias, true);
    }

    @Test
    public void testGenerateKeyPairInHSMForECCReference() {
        String alias = "alias-1";
        String applicationId = "TEST_APP";
        String referenceId = KeyReferenceIdConsts.EC_SECP256R1_SIGN.name();
        LocalDateTime now = DateUtils2.getUTCCurrentDateTime();

        KeyAlias currentRootAlias = Mockito.mock(KeyAlias.class);
        when(currentRootAlias.getAlias()).thenReturn("root-alias");
        Map<String, List<KeyAlias>> rootKeyAliasMap = new HashMap<>();
        rootKeyAliasMap.put(KeymanagerConstant.CURRENTKEYALIAS, Collections.singletonList(currentRootAlias));
        rootKeyAliasMap.put(KeymanagerConstant.KEYALIAS, Collections.singletonList(currentRootAlias));
        ReflectionTestUtils.setField(service, "rootKeyApplicationId", "ROOT");
        when(dbHelper.getKeyAliases("ROOT", KeymanagerConstant.EMPTY, now)).thenReturn(rootKeyAliasMap);

        KeyAlias latestKeyAlias = Mockito.mock(KeyAlias.class);
        when(latestKeyAlias.getAlias()).thenReturn("latest-alias");
        List<KeyAlias> keyAliasList = Collections.singletonList(latestKeyAlias);

        X509Certificate signingCert = Mockito.mock(X509Certificate.class);
        X500Principal principal = new X500Principal("CN=Test");
        when(keyStore.getCertificate("latest-alias")).thenReturn(signingCert);
        when(signingCert.getSubjectX500Principal()).thenReturn(principal);

        when(dbHelper.getExpiryPolicy(applicationId, now, keyAliasList)).thenReturn(now.plusDays(365));
        when(sanHelper.hasSANappIdAndRefId(applicationId, referenceId)).thenReturn(false);
        when(keymanagerUtil.getCertificateParameters(principal, now, now.plusDays(365))).thenReturn(certificateParameters);
        when(keymanagerUtil.isValidReferenceId(referenceId)).thenReturn(true);

        when(keyStore.getCertificate(alias)).thenReturn(x509Certificate);
        when(cryptomanagerUtil.getCertificateThumbprintInHex(x509Certificate)).thenReturn("thumb");
        when(keymanagerUtil.getUniqueIdentifier(anyString())).thenReturn("unique-id");

        ImmutablePair<String, X509Certificate> result = ReflectionTestUtils.invokeMethod(
                service, "generateKeyPairInHSM", alias, applicationId, referenceId, now, keyAliasList);

        assertNotNull(result);
        assertSame(x509Certificate, result.getRight());
    }

    @Test
    public void testGenerateKeyPairInHSMForEd25519WhenHSMSupported() {
        String alias = "alias-2";
        String applicationId = "TEST_APP";
        String referenceId = KeyReferenceIdConsts.ED25519_SIGN.name();
        LocalDateTime now = DateUtils2.getUTCCurrentDateTime();

        KeyAlias currentRootAlias = Mockito.mock(KeyAlias.class);
        when(currentRootAlias.getAlias()).thenReturn("root-alias");
        Map<String, List<KeyAlias>> rootKeyAliasMap = new HashMap<>();
        rootKeyAliasMap.put(KeymanagerConstant.CURRENTKEYALIAS, Collections.singletonList(currentRootAlias));
        rootKeyAliasMap.put(KeymanagerConstant.KEYALIAS, Collections.singletonList(currentRootAlias));
        ReflectionTestUtils.setField(service, "rootKeyApplicationId", "ROOT");
        when(dbHelper.getKeyAliases("ROOT", KeymanagerConstant.EMPTY, now)).thenReturn(rootKeyAliasMap);

        KeyAlias latestKeyAlias = Mockito.mock(KeyAlias.class);
        when(latestKeyAlias.getAlias()).thenReturn("latest-alias");
        List<KeyAlias> keyAliasList = Collections.singletonList(latestKeyAlias);

        X509Certificate signingCert = Mockito.mock(X509Certificate.class);
        X500Principal principal = new X500Principal("CN=Ed25519");
        when(keyStore.getCertificate("latest-alias")).thenReturn(signingCert);
        when(signingCert.getSubjectX500Principal()).thenReturn(principal);

        when(dbHelper.getExpiryPolicy(applicationId, now, keyAliasList)).thenReturn(now.plusDays(365));
        when(sanHelper.hasSANappIdAndRefId(applicationId, referenceId)).thenReturn(false);
        when(keymanagerUtil.getCertificateParameters(principal, now, now.plusDays(365))).thenReturn(certificateParameters);
        when(keymanagerUtil.isValidReferenceId(referenceId)).thenReturn(true);

        when(keyStore.getCertificate(alias)).thenReturn(x509Certificate);
        when(cryptomanagerUtil.getCertificateThumbprintInHex(x509Certificate)).thenReturn("thumb-ed");
        when(keymanagerUtil.getUniqueIdentifier(anyString())).thenReturn("unique-ed");

        ImmutablePair<String, X509Certificate> result = ReflectionTestUtils.invokeMethod(
                service, "generateKeyPairInHSM", alias, applicationId, referenceId, now, keyAliasList);
        
        assertNotNull(result);
        assertSame(x509Certificate, result.getRight());
    }

    @Test
    public void testGetLatestCertPrincipal() {
        KeyAlias keyAlias = Mockito.mock(KeyAlias.class);
        when(keyAlias.getAlias()).thenReturn("alias-3");
        when(keyStore.getCertificate("alias-3")).thenReturn(x509Certificate);

        X500Principal principal = new X500Principal("CN=PrincipalTest");
        when(x509Certificate.getSubjectX500Principal()).thenReturn(principal);

        List<KeyAlias> keyAliasList = Arrays.asList(keyAlias);
        X500Principal result = ReflectionTestUtils.invokeMethod(service, "getLatestCertPrincipal", keyAliasList);

        assertSame(principal, result);
        verify(keyStore).getCertificate("alias-3");
    }

    @Test
    public void testGenerateKeyPairInHSMWithSAN() {
        String alias = "alias-san";
        String applicationId = "TEST_APP";
        String referenceId = KeyReferenceIdConsts.EC_SECP256R1_SIGN.name();
        LocalDateTime now = DateUtils2.getUTCCurrentDateTime();

        KeyAlias currentRootAlias = Mockito.mock(KeyAlias.class);
        when(currentRootAlias.getAlias()).thenReturn("root-alias");
        Map<String, List<KeyAlias>> rootKeyAliasMap = new HashMap<>();
        rootKeyAliasMap.put(KeymanagerConstant.CURRENTKEYALIAS, Collections.singletonList(currentRootAlias));
        rootKeyAliasMap.put(KeymanagerConstant.KEYALIAS, Collections.singletonList(currentRootAlias));
        ReflectionTestUtils.setField(service, "rootKeyApplicationId", "ROOT");
        when(dbHelper.getKeyAliases("ROOT", KeymanagerConstant.EMPTY, now)).thenReturn(rootKeyAliasMap);

        KeyAlias latestKeyAlias = Mockito.mock(KeyAlias.class);
        when(latestKeyAlias.getAlias()).thenReturn("latest-alias");
        List<KeyAlias> keyAliasList = Collections.singletonList(latestKeyAlias);

        X509Certificate signingCert = Mockito.mock(X509Certificate.class);
        X500Principal principal = new X500Principal("CN=Test");
        when(keyStore.getCertificate("latest-alias")).thenReturn(signingCert);
        when(signingCert.getSubjectX500Principal()).thenReturn(principal);

        when(dbHelper.getExpiryPolicy(applicationId, now, keyAliasList)).thenReturn(now.plusDays(365));
        when(sanHelper.hasSANappIdAndRefId(applicationId, referenceId)).thenReturn(true);
        when(keymanagerUtil.isValidReferenceId(referenceId)).thenReturn(true);

        when(keyStore.getCertificate(alias)).thenReturn(x509Certificate);
        when(cryptomanagerUtil.getCertificateThumbprintInHex(x509Certificate)).thenReturn("thumb-san");
        when(keymanagerUtil.getUniqueIdentifier(anyString())).thenReturn("unique-san");

        ImmutablePair<String, X509Certificate> result = ReflectionTestUtils.invokeMethod(
                service, "generateKeyPairInHSM", alias, applicationId, referenceId, now, keyAliasList);

        assertNotNull(result);
        assertSame(x509Certificate, result.getRight());
    }

    @Test
    public void testGenerateKeyPairInHSMForRSAReference() {
        String alias = "alias-rsa";
        String applicationId = "TEST_APP";
        String referenceId = "SIGN";
        LocalDateTime now = DateUtils2.getUTCCurrentDateTime();

        KeyAlias currentRootAlias = Mockito.mock(KeyAlias.class);
        when(currentRootAlias.getAlias()).thenReturn("root-alias");
        Map<String, List<KeyAlias>> rootKeyAliasMap = new HashMap<>();
        rootKeyAliasMap.put(KeymanagerConstant.CURRENTKEYALIAS, Collections.singletonList(currentRootAlias));
        rootKeyAliasMap.put(KeymanagerConstant.KEYALIAS, Collections.singletonList(currentRootAlias));
        ReflectionTestUtils.setField(service, "rootKeyApplicationId", "ROOT");
        when(dbHelper.getKeyAliases("ROOT", KeymanagerConstant.EMPTY, now)).thenReturn(rootKeyAliasMap);

        KeyAlias latestKeyAlias = Mockito.mock(KeyAlias.class);
        when(latestKeyAlias.getAlias()).thenReturn("latest-alias");
        List<KeyAlias> keyAliasList = Collections.singletonList(latestKeyAlias);

        X509Certificate signingCert = Mockito.mock(X509Certificate.class);
        X500Principal principal = new X500Principal("CN=RSA");
        when(keyStore.getCertificate("latest-alias")).thenReturn(signingCert);
        when(signingCert.getSubjectX500Principal()).thenReturn(principal);

        when(dbHelper.getExpiryPolicy(applicationId, now, keyAliasList)).thenReturn(now.plusDays(365));
        when(sanHelper.hasSANappIdAndRefId(applicationId, referenceId)).thenReturn(false);
        when(keymanagerUtil.getCertificateParameters(principal, now, now.plusDays(365))).thenReturn(certificateParameters);
        when(keymanagerUtil.isValidReferenceId(referenceId)).thenReturn(false);

        when(keyStore.getCertificate(alias)).thenReturn(x509Certificate);
        when(cryptomanagerUtil.getCertificateThumbprintInHex(x509Certificate)).thenReturn("thumb-rsa");
        when(keymanagerUtil.getUniqueIdentifier(anyString())).thenReturn("unique-rsa");

        ImmutablePair<String, X509Certificate> result = ReflectionTestUtils.invokeMethod(
                service, "generateKeyPairInHSM", alias, applicationId, referenceId, now, keyAliasList);

        assertNotNull(result);
        assertSame(x509Certificate, result.getRight());
    }
}
