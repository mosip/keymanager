package io.mosip.kernel.signature.service;

import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.signature.dto.*;

public interface SignatureService {
	/**
	 * Validate signature
	 * 
	 * @param timestampRequestDto {@link TimestampRequestDto}
	 * @return {@link ValidatorResponseDto}
	 */
	@Deprecated
	public ValidatorResponseDto validate(TimestampRequestDto timestampRequestDto);

	/**
	 * Sign Data.
	 *
	 * @param signRequestDto the signRequestDto
	 * @return the SignatureResponse
	 */
	@Deprecated
	public SignatureResponse sign(SignRequestDto signRequestDto);


	public SignatureResponseDto signPDF(PDFSignatureRequestDto request);

	/**
	 * JSON Web Signature(JWS) for the input data using RS256 algorithm
	 *
	 * @param jwtSignRequestDto the jwtSignRequestDto
	 * @return the JWTSignatureResponseDto
	 */
	public JWTSignatureResponseDto jwtSign(JWTSignatureRequestDto jwtSignRequestDto);

	/**
	 * JWT Signature verification.
	 *
	 * @param jwtSignatureVerifyRequestDto the jwtSignatureVerifyRequestDto
	 * @return the JWTSignatureVerifyResponseDto
	 */
	public JWTSignatureVerifyResponseDto jwtVerify(JWTSignatureVerifyRequestDto jwtSignatureVerifyRequestDto);


	/**
	 * JSON Web Signature(JWS) for the input data using input algorithm
	 *
	 * @param jwsSignRequestDto the JWSSignatureRequestDto
	 * @return the JWTSignatureResponseDto
	 */
	public JWTSignatureResponseDto jwsSign(JWSSignatureRequestDto jwsSignRequestDto);

}
