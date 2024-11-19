package io.mosip.kernel.keymanagerservice.constant;

import java.time.format.DateTimeFormatter;

/**
 * Constants for Keymanager
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
public class KeymanagerConstant {

	/**
	 * Private constructor for KeyManagerConstant
	 */
	private KeymanagerConstant() {
	}

	/**
	 * The constant Whitespace
	 */
	public static final String WHITESPACE = " ";

	/**
	 * The constant EMPTY
	 */
	public static final String EMPTY = "";

	/**
	 * The constant keyalias
	 */
	public static final String KEYALIAS = "keyAlias";

	/**
	 * The constant currentkeyalias
	 */
	public static final String CURRENTKEYALIAS = "currentKeyAlias";

	/**
	 * The constant timestamp
	 */
	public static final String TIMESTAMP = "timestamp";

	/**
	 * The constant sessionID
	 */
	public static final String SESSIONID = "sessionId";

	/**
	 * The constant applicationId
	 */
	public static final String APPLICATIONID = "applicationId";

	/**
	 * The constant referenceId
	 */
	public static final String REFERENCEID = "referenceId";

	/**
	 * The constant Request received to getPublicKey
	 */
	public static final String GET_CERTIFICATE = "Request received to getCertificate";

	/**
	 * The constant Getting public key from DB Store
	 */
	public static final String GETPUBLICKEYDB = "Getting Certificate from DB Store";

	/**
	 * The constant Getting public key from SoftHSM
	 */
	public static final String GETPUBLICKEYHSM = "Getting Certificate from KeyStore.";

	/**
	 * The constant Getting key alias
	 */
	public static final String GETALIAS = "Getting key alias";

	/**
	 * The constant Getting expiry policy
	 */
	public static final String GETEXPIRYPOLICY = "Getting expiry policy";

	/**
	 * The constant Request received to decryptSymmetricKey
	 */
	public static final String DECRYPTKEY = "Request received to decryptSymmetricKey";

	/**
	 * The constant Getting private key
	 */
	public static final String GETPRIVATEKEY = "Getting private key";

	/**
	 * The constant Storing key in KeyAlias
	 */
	public static final String STOREKEYALIAS = "Storing key in KeyAlias";

	/**
	 * The constant Storing key in dbKeyStore
	 */
	public static final String STOREDBKEY = "Storing key in dbKeyStore";

	/**
	 * The constant keyFromDBStore
	 */
	public static final String KEYFROMDB = "keyFromDBStore";

	/**
	 * The constant keyPolicy
	 */
	public static final String KEYPOLICY = "keyPolicy";

	/**
	 * The constant symmetricKeyRequestDto
	 */
	public static final String SYMMETRICKEYREQUEST = "symmetricKeyRequestDto";

	/**
	 * The constant fetchedKeyAlias
	 */
	public static final String FETCHEDKEYALIAS = "fetchedKeyAlias";

	/**
	 * The constant dbKeyStore
	 */
	public static final String DBKEYSTORE = "dbKeyStore";

	/**
	 * The constant RSA
	 */
	public static final String RSA = "RSA";

	/**
	 * The constant INVALID_REQUEST
	 */
	public static final String INVALID_REQUEST = "should not be null or empty";

	public static final String STORECERTIFICATE = "Storing certificate";

	/**
	 * The constant INVALID_REQUEST
	 */
	public static final String REQUEST_FOR_MASTER_KEY_GENERATION = "Request for Master Key Generation";

	public static final String REQUEST_TYPE_CERTIFICATE = "CERTIFICATE";

	public static final String REQUEST_TYPE_CSR = "CSR";

	public static final String ROOT_KEY = "Root Key"; 

	public static final String CERTIFICATE_TYPE = "X.509";

	public static final String BASE_KEY_POLICY_CONST = "BASE";

	public static final String UPLOAD_SUCCESS = "Upload Success";

	public static final String CERTIFICATE_PARSE = "CERTIFICATE_PARSE";

	/**
	 * The constant KeyStore PrivateKey NotAvailable
	 */
	public static final String KS_PK_NA = "NA";

	public static final String ROOT = "ROOT";

	public static final String REQ_SYM_KEY_GEN = "Request for Symmetric Key Generation.";

	public static final int SYMMETRIC_KEY_VALIDITY = 365 * 10;

	public static final String GENERATE_SUCCESS = "Generation Success";

	public static final String SYMM_KEY_EXISTS = "Key Exists.";

	public static final String REQ_REV_KEY = "Request for key revocation.";

	public static final String KEY_REVOKED = "Key Revoked";

	public static final String ENCRYPTION_KEY = "EncryptionKey";

	public static final String KERNEL_APP_ID = "KERNEL";

	public static final String KERNEL_IDENTIFY_CACHE = "IDENTITY_CACHE";

	public static final String VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITH_REFERENCE_ID = "Valid reference Id. Getting key alias with referenceId";

	public static final String NOT_A_VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITHOUT_REFERENCE_ID = "Not a valid reference Id. Getting key alias without referenceId";

	public static final String PARTNER_APP_ID = "PARTNER";

	public static final String HYPHEN = "-";

	public static final String DATE_FORMAT = "MM-dd-yyyy";

	public static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern(DATE_FORMAT);

	public static final String UNDER_SCORE = "_";

	public static final String COMPONENT_MASTER_KEY_DUMMY_REF = "COMP_MASTER";

	public static final String ALL_GET_CERTIFICATES = "Request received to get all the Certificates";

	public static final String DOT = ".";

	public static final String COMMA = ",";

	public static final String GENERATE_ECC_MASTER_KEY = "Request received to generate the ECC Master Key pair.";

	public static final String ECC_CURVE = "Curve";

	public static final String MISSING_INPUT_PARAMETER = "Missing Input Parameter - ";

	public static final String VALIDATE = "Validate";

	public static final String INVALID_CURVE_VALUE = "Invalid Curve Value - ";

	public static final String IDA_APP_ID = "IDA";

	public static final String EC_KEY_TYPE = "EC";

	public static final String ED25519_KEY_TYPE = "Ed25519";

	public static final String EDDSA_KEY_TYPE = "EdDSA";

	public static final String ED25519_ALG_OID = "1.3.101.112";

	public static final String APP_REF_ID_SEP = "#";
}
