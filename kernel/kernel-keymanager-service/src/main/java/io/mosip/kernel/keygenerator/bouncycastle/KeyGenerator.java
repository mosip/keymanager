package io.mosip.kernel.keygenerator.bouncycastle;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.keygenerator.bouncycastle.util.KeyGeneratorUtils;

/**
 * This class generates asymmetric and symmetric key pairs
 * 
 * @author Urvil Joshi
 *
 * @since 1.0.0
 */
@Component
public class KeyGenerator {

	private SecureRandom secureRandom;
	/**
	 * Symmetric key algorithm Name
	 */
	@Value("${mosip.kernel.keygenerator.symmetric-algorithm-name}")
	private String symmetricKeyAlgorithm;

	/**
	 * Symmetric key length
	 */
	@Value("${mosip.kernel.keygenerator.symmetric-key-length}")
	private int symmetricKeyLength;

	/**
	 * Asymmetric key algorithm Name
	 */
	@Value("${mosip.kernel.keygenerator.asymmetric-algorithm-name}")
	private String asymmetricKeyAlgorithm;

	/**
	 * Asymmetric key length
	 */
	@Value("${mosip.kernel.keygenerator.asymmetric-key-length}")
	private int asymmetricKeyLength;

	/**
	 * Asymmetric key algorithm Name
	 */
	@Value("${mosip.kernel.keygenerator.rng.provider.enable:true}")
	private boolean rngProviderEnabled;

	/**
	 * Asymmetric key algorithm Name
	 */
	@Value("${mosip.kernel.keygenerator.rng.provider.name:PKCS11}")
	private String rngProviderName;

	@Value("${mosip.kernel.keygenerator.asymmetric.ed25519.algorithm-name:Ed25519}")
	private String asymmetricEDKeyAlgorithm;

	@Autowired
	private ECKeyStore keyStore;

	/**
	 * This method generates symmetric key
	 * 
	 * @return generated {@link SecretKey}
	 */
	public SecretKey getSymmetricKey() {
		javax.crypto.KeyGenerator generator = KeyGeneratorUtils.getKeyGenerator(symmetricKeyAlgorithm,
				symmetricKeyLength, getSecureRandom());
		return generator.generateKey();
	}

	/**
	 * This method generated Asymmetric key pairs
	 * 
	 * @return {@link KeyPair} which contain public nad private key
	 */
	public KeyPair getAsymmetricKey() {
		KeyPairGenerator generator = KeyGeneratorUtils.getKeyPairGenerator(asymmetricKeyAlgorithm, asymmetricKeyLength, 
						getSecureRandom());
		return generator.generateKeyPair();
	}

	public KeyPair getEd25519KeyPair() {
		KeyPairGenerator generator = KeyGeneratorUtils.getEdKeyPairGenerator(asymmetricEDKeyAlgorithm, getSecureRandom());
		return generator.generateKeyPair();
	}

	public PrivateKey buildPrivateKey(byte[] privateKeyData) {
		return KeyGeneratorUtils.generatePrivate(asymmetricEDKeyAlgorithm, privateKeyData);
	}

	private SecureRandom getSecureRandom() {
		if (Objects.nonNull(secureRandom)) {
			return secureRandom;
		}
		if (!rngProviderEnabled) {
			secureRandom = new SecureRandom();
			return secureRandom; 
		}
		try {
			secureRandom = SecureRandom.getInstance(rngProviderName, keyStore.getKeystoreProviderName());
			return secureRandom;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// ignoring this exception, because SecureRandom will be initialised with no argument (defaults to SHA1PRNG) 
		}
		secureRandom = new SecureRandom();
		return secureRandom;
	}

}
