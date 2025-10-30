package io.mosip.kernel.keygenerator.bouncycastle.test;

import static org.hamcrest.CoreMatchers.isA;
import static org.junit.Assert.assertThat;
import static reactor.core.publisher.Mono.when;

import java.security.KeyPair;
import java.security.NoSuchProviderException;

import javax.crypto.SecretKey;

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

	@Test
	public void testGetSymmetricKey() {
		assertThat(keyGenerator.getSymmetricKey(), isA(SecretKey.class));
	}

	@Test
	public void testGetAsymmetricKey() {
		assertThat(keyGenerator.getAsymmetricKey(), isA(KeyPair.class));
	}

    @Test
    public void testGetSecureRandom() {
        ReflectionTestUtils.setField(keyGenerator, "rngProviderName", "PKCS11");
        ReflectionTestUtils.setField(keyGenerator, "rngProviderEnabled", true);
        try {
            assertThat(keyGenerator.getSymmetricKey(), isA(SecretKey.class));
        } catch (Exception e) {
            ReflectionTestUtils.setField(keyGenerator, "rngProviderEnabled", false);
            assertThat(keyGenerator.getSymmetricKey(), isA(SecretKey.class));
        }
    }
}
