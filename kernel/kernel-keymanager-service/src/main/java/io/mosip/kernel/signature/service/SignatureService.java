package io.mosip.kernel.signature.service;

import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.signature.dto.*;

import java.security.cert.Certificate;
import java.util.List;

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

	/**
	 * JSON Web Signature(JWS) for the input data using RS256 algorithm
	 *
	 * @param jwtSignRequestDto the jwtSignRequestDto
	 * @return the JWTSignatureResponseDto
	 */
	public JWTSignatureResponseDto jwtSignV2(JWTSignatureRequestDtoV2 jwtSignRequestDto);

	/**
	 * JSON Web Signature(JWS) for the input data using input algorithm
	 *
	 * @param jwsSignRequestDto the JWSSignatureRequestDto
	 * @return the JWTSignatureResponseDto
	 */
	public JWTSignatureResponseDto jwsSignV2(JWSSignatureRequestDtoV2 jwsSignRequestDto);

	/**
	 * JWT Signature verification.
	 *
	 * @param jwtSignatureVerifyRequestDto the jwtSignatureVerifyRequestDto
	 * @return the JWTSignatureVerifyResponseDto
	 */
	public JWTSignatureVerifyResponseDto jwtVerifyV2(JWTSignatureVerifyRequestDto jwtSignatureVerifyRequestDto);

	/**
	 * Validate trust for the given JWT signature verify request.
	 *
	 * @param jwtVerifyRequestDto the JWTSignatureVerifyRequestDto
	 * @param headerCertificate   the certificate from the JWT header
	 * @param reqCertData         the certificate data from the request
	 * @return a String indicating the validation result
	 */
	public String validateTrust(JWTSignatureVerifyRequestDto jwtVerifyRequestDto, Certificate headerCertificate, String reqCertData);

	/**
	 * Validate trust for the given JWT signature verify request with Certificate Chain.
	 *
	 * @param jwtVerifyRequestDto the JWTSignatureVerifyRequestDto
	 * @param headerCertificates   the list of certificates from the JWT header
	 * @param reqCertData         the certificate data from the request
	 * @return a String indicating the validation result
	 */
	public String validateTrustV2(JWTSignatureVerifyRequestDto jwtVerifyRequestDto, List<Certificate> headerCertificates, String reqCertData);

}
