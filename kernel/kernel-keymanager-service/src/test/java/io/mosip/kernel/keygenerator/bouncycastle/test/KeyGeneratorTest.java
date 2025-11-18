package io.mosip.kernel.keygenerator.bouncycastle.test;

import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;

import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.keygenerator.bouncycastle.KeyGenerator;
import org.springframework.test.util.ReflectionTestUtils;

@SpringBootTest
@RunWith(SpringRunner.class)
public class KeyGeneratorTest {

    @Autowired
    KeyGenerator keyGenerator;

    @MockBean
    private ECKeyStore keyStore;

    @Before
    public void init() {
        ReflectionTestUtils.setField(keyGenerator, "secureRandom", null);
    }

    @Test
    public void testGetSymmetricKey() {
        assertThat(keyGenerator.getSymmetricKey(), isA(SecretKey.class));
    }

    @Test
    public void testGetAsymmetricKey() {
        assertThat(keyGenerator.getAsymmetricKey(), isA(KeyPair.class));
    }

    @Test
    public void getSymmetricKeyTest() {
        SecretKey key = keyGenerator.getSymmetricKey();
        assertThat(key, isA(SecretKey.class));
        assertNotNull(key.getEncoded());
        assertTrue(key.getEncoded().length > 0);
    }

    @Test
    public void getAsymmetricKeyTest() {
        KeyPair keyPair = keyGenerator.getAsymmetricKey();
        assertThat(keyPair, isA(KeyPair.class));
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
    }

    @Test
    public void testBuildPrivateKey() {
        KeyPair keyPair = keyGenerator.getEd25519KeyPair();
        byte[] privateKeyData = keyPair.getPrivate().getEncoded();
        PrivateKey rebuiltKey = keyGenerator.buildPrivateKey(privateKeyData);
        assertNotNull(rebuiltKey);
    }

    @Test
    public void testSecureRandomCaching() {
        ReflectionTestUtils.setField(keyGenerator, "secureRandom", new SecureRandom());
        SecureRandom result = (SecureRandom) ReflectionTestUtils.invokeMethod(keyGenerator, "getSecureRandom");
        assertNotNull(result);
    }

    @Test
    public void testSecureRandomRngDisabled() {
        ReflectionTestUtils.setField(keyGenerator, "rngProviderEnabled", false);
        SecureRandom result = (SecureRandom) ReflectionTestUtils.invokeMethod(keyGenerator, "getSecureRandom");
        assertNotNull(result);
    }

    @Test
    public void testSecureRandomRngEnabled() {
        when(keyStore.getKeystoreProviderName()).thenReturn("SUN");
        ReflectionTestUtils.setField(keyGenerator, "rngProviderEnabled", true);
        ReflectionTestUtils.setField(keyGenerator, "rngProviderName", "SHA1PRNG");
        SecureRandom result = (SecureRandom) ReflectionTestUtils.invokeMethod(keyGenerator, "getSecureRandom");
        assertNotNull(result);
    }

    @Test
    public void testSecureRandomFallback() {
        when(keyStore.getKeystoreProviderName()).thenReturn("SUN");
        ReflectionTestUtils.setField(keyGenerator, "rngProviderEnabled", true);
        ReflectionTestUtils.setField(keyGenerator, "rngProviderName", "INVALID_PROVIDER");
        SecureRandom result = (SecureRandom) ReflectionTestUtils.invokeMethod(keyGenerator, "getSecureRandom");
        assertNotNull(result);
    }

}
