package io.mosip.kernel.signature.constant;

/**
 * Constants for CryptoSignaure
 * 
 * @author Uday Kumarl
 * @since 1.0.0
 *
 */
public enum SignatureErrorCode {
	REQUEST_DATA_NOT_VALID("KER-CSS-999", "Invalid request input"),

	NOT_VALID("KER-CSS-101", "Validation Unsuccessful"),
	
	INVALID_INPUT("KER-JWS-102", "Data to sign is not valid."),

	INVALID_JSON("KER-JWS-103", "Data to sign is not valid JSON."),

	SIGN_ERROR("KER-JWS-104", "Error - Unable to sign the data."),

	VERIFY_ERROR("KER-JWS-105", "Error - Unable to verify the data."),

	INVALID_VERIFY_INPUT("KER-JWS-106", "Signature data to verify not valid."),

	CERT_NOT_VALID("KER-JWS-107", "Signature verification certificate not valid."),

	SIGN_NOT_ALLOWED("KER-JWS-108", "Signing data not allowed for the authenticated token."),

	INTERNAL_SERVER_ERROR("KER-CSS-500", "Internal server error"),

	COSE_SIGN_ERROR("KER-CWS-109", "Error - Unable to sign the data."),

	COSE_VERIFY_ERROR("KER-CWS-110", "Error - Unable to verify the data."),

    INVALID_CWT_INPUT("KER-CWS-111", "Error - Invalid CWT Signed input."),

    INVALID_COSE_SIGN1_INPUT("KER-CWS-112", "Error - Invalid COSE Sign1."),

    SIGN_ALGO_NOT_SUPPORTED("KER-SIG-113", "Signature Algorithm Not Supported"),

    DATA_PARSING_ERROR("KER-SIG-114", "Input data parsing error.");

	private final String errorCode;
	private final String errorMessage;

	private SignatureErrorCode(final String errorCode, final String errorMessage) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

}
