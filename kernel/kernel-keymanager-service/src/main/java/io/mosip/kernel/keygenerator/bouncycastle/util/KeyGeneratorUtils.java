package io.mosip.kernel.keygenerator.bouncycastle.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.mosip.kernel.core.exception.NoSuchAlgorithmException;
import io.mosip.kernel.keygenerator.bouncycastle.constant.KeyGeneratorExceptionConstant;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;

/**
 * This is a utils class for keygenerator
 * 
 * @author Urvil Joshi
 *
 * @since 1.0.0
 */
public class KeyGeneratorUtils {

	/**
	 * Bouncy-Castle provider instance
	 */
	private static BouncyCastleProvider provider;
	
	static {
		provider = init();
	}

	/**
	 * No Args Constructor for this class
	 */
	private KeyGeneratorUtils() {
	}

	// Added this method to load the clazz in JVM
	public static void loadClazz() {
	}

	/**
	 * This class configures {@link KeyGenerator}
	 * 
	 * @param algorithmName algorithm name as configured
	 * @param keylength     key-length as configured
	 * @return configured {@link KeyGenerator} instance
	 */
	public static javax.crypto.KeyGenerator getKeyGenerator(String algorithmName, int keylength, SecureRandom secureRandom) {

		javax.crypto.KeyGenerator generator = null;
		try {
			generator = javax.crypto.KeyGenerator.getInstance(algorithmName, provider);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmException(
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
		}
		generator.init(keylength, secureRandom);
		return generator;
	}

	/**
	 * This class configures {@link KeyPairGenerator}
	 * 
	 * @param algorithmName algorithm name as configured
	 * @param keylength     key-length as configured
	 * @return configured {@link KeyPairGenerator} instance
	 */
	public static KeyPairGenerator getKeyPairGenerator(String algorithmName, int keylength, SecureRandom secureRandom) {

		KeyPairGenerator generator = null;
		try {
			generator = KeyPairGenerator.getInstance(algorithmName, provider);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmException(
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
		}
		generator.initialize(keylength, secureRandom);
		return generator;
	}

	public static KeyPairGenerator getEdKeyPairGenerator(String algorithmName, SecureRandom secureRandom) {

		KeyPairGenerator generator = null;
		try {
			generator = KeyPairGenerator.getInstance(algorithmName, provider);
			generator.initialize(new ECGenParameterSpec(algorithmName), secureRandom);
			return generator;
		} catch (java.security.NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new NoSuchAlgorithmException(
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
		}
		
	}

	public static PrivateKey generatePrivate(String algorithmName, byte[] privateKeyData) {
		try {
			return KeyFactory.getInstance(algorithmName, provider).generatePrivate(new PKCS8EncodedKeySpec(privateKeyData));
		} catch (InvalidKeySpecException | java.security.NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmException(
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
		}
	}

	public static PublicKey createPublicKey(String algorithmName, byte[] publicKeyData) {
		try {
			return KeyFactory.getInstance(KeymanagerConstant.ED25519_KEY_TYPE, provider)
											    .generatePublic(new X509EncodedKeySpec(publicKeyData));
		} catch(InvalidKeySpecException | java.security.NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmException(
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
					KeyGeneratorExceptionConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
		}
		
	}


	/**
	 * Initialize by adding bouncy castle provider in JVM.
	 * 
	 * @return {@link BouncyCastleProvider}
	 */
	private static BouncyCastleProvider init() {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		return provider;
	}
}
