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

	public static final String EC_SECP256K1_SIGN = "EC_SECP256K1_SIGN";

	public static final String EC_SECP256R1_SIGN = "EC_SECP256R1_SIGN";

	public static final String ED25519_SIGN = "ED25519_SIGN";

	public static final String ISSUER = "iss";

	public static final String KEY_ID_PREFIX = "PAYLOAD_ISSUER";

	public static final String KEY_ID_SEPARATOR = "#";

	public static final String RAW_SIGN = "RAW_SIGN";

	public static final String BASE58BTC = "base58btc";

	public static final String BASE64URL = "base64url";

	public static final String JWS_HEADER_JWK_URL = "jku";

	public static final String JWS_HEADER_CONTENT_TYPE = "cty";

	public static final String JWS_HEADER_TYPE_KEY = "typ";

	public static final String JWS_HEADER_CRTICAL_PARAM = "crit";

	public static final String COSE_SIGN = "COSESign";

	public static final String COSE_VERIFY = "COSEVerify";

	public static final String COSE_HEADER_CRITICAL_PARAM = "crit";

	public static final String COSE_HEADER_CONTENT_TYPE = "content-type";

	public static final String COSE_HEADER_IV = "iv";

	public static final String COSE_HEADER_PARTIAL_IV = "partial-iv";

	public static final String COSE_HEADER_KEY_ID = "kid";

	public static final String INCLUDE_CERTIFICATE = "includeCertificate";

	public static final String INCLUDE_CERTIFICATE_CHAIN = "includeCertificateChain";

	public static final String INCLUDE_CERTIFICATE_HASH = "includeCertificateHash";

	public static final String CERTIFICATE_URL = "certificateUrl";

    public static final String RSA_PS256_SIGN_ALGORITHM_INSTANCE = "SHA256withRSAandMGF1";

	public static final String BC_PROVIDER = "BC";
}
