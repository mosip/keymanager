package io.mosip.kernel.signature.constant;

/**
 * Constant class for Signature Constant Service
 * 
 * @author Uday Kumar
 *
 * @since 1.0.0
 */
public class SignatureConstant {
	/**
	 * Private Constructor for this class
	 */
	private SignatureConstant() {

	}

	public static final String VALIDATION_SUCCESSFUL = "Validation Successful";
	public static final String SUCCESS = "success";

	public static final String SESSIONID = "SignatureSessionId";

	public static final String JWT_SIGN = "JWTSignature";

	public static final String BLANK = "";

	public static final Boolean DEFAULT_INCLUDES = false;

	public static final String JWT_HEADER_CERT_KEY = "x5c";

	public static final String PERIOD = "\\.";

	public static final String VALIDATION_FAILED = "Validation Failed";

	public static final String TRUST_NOT_VERIFIED = "TRUST_NOT_VERIFIED";

	public static final String TRUST_NOT_VERIFIED_NO_DOMAIN = "TRUST_NOT_VERIFIED_NO_DOMAIN";

	public static final String TRUST_NOT_VALID = "TRUST_CERT_PATH_NOT_VALID";

	public static final String TRUST_VALID = "TRUST_CERT_PATH_VALID";

	public static final String JWS_SIGN = "JWSSignature";

	public static final String JWS_PS256_SIGN_ALGO_CONST = "PS256";

	public static final String JWS_RS256_SIGN_ALGO_CONST = "RS256";

	public static final String B64 = "b64";

	public static final String RS256_ALGORITHM = "SHA256withRSA";

	public static final String PS256_ALGORITHM = "RSASSA-PSS";

	public static final String PSS_PARAM_SHA_256 = "SHA-256";  

	public static final String PSS_PARAM_MGF1 = "MGF1";

	public static final int PSS_PARAM_SALT_LEN = 32;

	public static final int PSS_PARAM_TF = 1;

	public static final String REF_ID_SIGN_CONST = "SIGN";

	public static final String EC256_ALGORITHM = "SHA256withECDSA";

	public static final int EC256_SIGNATURE_LENGTH = 64;

	public static final String ED25519_ALGORITHM = "Ed25519";

	public static final String JWS_ES256_SIGN_ALGO_CONST = "ES256";

	public static final String JWS_ES256K_SIGN_ALGO_CONST = "ES256K";

	public static final String JWS_EDDSA_SIGN_ALGO_CONST = "EdDSA";
}
