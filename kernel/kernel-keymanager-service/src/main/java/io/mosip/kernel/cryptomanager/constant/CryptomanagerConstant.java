package io.mosip.kernel.cryptomanager.constant;

/**
 * Constant class for Crypto-Manager-Service
 * 
 * @author Urvil Joshi
 *
 * @since 1.0.0
 */
public class CryptomanagerConstant {
	/**
	 * Private Constructor for this class
	 */
	private CryptomanagerConstant() {

	}

	public static final String WHITESPACE = " ";
	public static final String INVALID_REQUEST = "should not be null or empty";
	public static final String EMPTY_ATTRIBUTE = "should not be empty";
	public static final String EMPTY_REGEX = ".+\\S.*";

	public static final String SESSIONID = "CryptoManagerSession";

	public static final String ENCRYPT = "CryptoManagerEncrypt";

	public static final String DECRYPT = "CryptoManagerDecrypt";

	public static final int THUMBPRINT_LENGTH = 32;

	public static final int ENCRYPTED_SESSION_KEY_LENGTH = 256;

	public static final byte[] VERSION_RSA_2048 = "VER_R2".getBytes();

	public static final int GCM_AAD_LENGTH = 32; 

	public static final int GCM_NONCE_LENGTH = 12; 

	public static final String ENCRYPT_PIN = "CryptoManagerEncryptWithPin";

	public static final String DECRYPT_PIN = "CryptoManagerDecryptWithPin";

	public static final String NOT_APPLICABLE = "NA";

	public static final String JWT_ENCRYPT = "Crypto-Manager-JWEEncrypt";

	public static final String JWT_DECRYPT = "Crypto-Manager-JWEDecrypt";

	public static final Boolean DEFAULT_INCLUDES_FALSE = false;

	public static final Boolean DEFAULT_INCLUDES_TRUE = true;

	public static final String JSON_CONTENT_TYPE_KEY = "cty";

	public static final String JSON_CONTENT_TYPE_VALUE = "JWT";

	public static final String JSON_HEADER_JWK_KEY = "jku";

	public static final String JSON_HEADER_TYPE_KEY = "typ";

	public static final String GEN_ARGON2_HASH = "Crypto-Manager-Gen-Argon2-Hash";

	public static final String CACHE_AES_KEY = "cacheAESKey";

	public static final String CACHE_INT_COUNTER = "cacheIntCounter";

	public static final byte[] VERSION_EC256_R1 = "VER_E2".getBytes(); // secp256R1 curve header

	public static final byte[] VERSION_EC256_K1 = "VER_K2".getBytes(); // secp256K1 curve header

	public static final byte[] VERSION_EC_X25519 = "VER_X2".getBytes(); // X25519 curve header

	public static final String EC_SECP256R1 = "SECP256R1";

	public static final String EC_SECP256K1 = "SECP256K1";

	public static final String EC_X25519 = "X25519";
	
}

