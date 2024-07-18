package io.mosip.kernel.signature.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.JsonWebSignatureAlgorithm;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JWSHeader;

import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.pdfgenerator.model.Rectangle;
import io.mosip.kernel.core.pdfgenerator.spi.PDFGenerator;
import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.kernel.core.util.exception.JsonMappingException;
import io.mosip.kernel.core.util.exception.JsonParseException;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keygenerator.bouncycastle.util.KeyGeneratorUtils;
import io.mosip.kernel.keymanagerservice.constant.KeyReferenceIdConsts;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.dto.PublicKeyResponse;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.partnercertservice.dto.CertificateTrustRequestDto;
import io.mosip.kernel.partnercertservice.dto.CertificateTrustResponeDto;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;
import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.dto.JWTSignatureVerifyRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureVerifyResponseDto;
import io.mosip.kernel.signature.dto.PDFSignatureRequestDto;
import io.mosip.kernel.signature.dto.SignRequestDto;
import io.mosip.kernel.signature.dto.SignatureRequestDto;
import io.mosip.kernel.signature.dto.SignatureResponseDto;
import io.mosip.kernel.signature.dto.TimestampRequestDto;
import io.mosip.kernel.signature.dto.ValidatorResponseDto;
import io.mosip.kernel.signature.exception.CertificateNotValidException;
import io.mosip.kernel.signature.exception.PublicKeyParseException;
import io.mosip.kernel.signature.exception.RequestException;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.service.SignatureProvider;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.util.SignatureUtil;
import jakarta.annotation.PostConstruct;

/**
 * @author Uday Kumar
 * @author Urvil
 *
 */
@Service
public class SignatureServiceImpl implements SignatureService {

	private static final Logger LOGGER = KeymanagerLogger.getLogger(SignatureServiceImpl.class);

	@Autowired
	private KeymanagerService keymanagerService;

	@Autowired
	private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

	@Value("${mosip.kernel.keygenerator.asymmetric-algorithm-name}")
	private String asymmetricAlgorithmName;

	/** The sign applicationid. */
	@Value("${mosip.sign.applicationid:KERNEL}")
	private String signApplicationid;

	/** The sign refid. */
	@Value("${mosip.sign.refid:SIGN}")
	private String signRefid;

	@Value("${mosip.kernel.crypto.sign-algorithm-name:RS256}")
	private String signAlgorithm;

	@Value("${mosip.kernel.keymanager.jwtsign.validate.json:true}")
	private boolean confValidateJson;

	@Value("${mosip.kernel.keymanager.jwtsign.include.keyid:true}")
	private boolean includeKeyId;

	@Value("${mosip.kernel.keymanager.jwtsign.enable.secp256k1.algorithm:true}")
	private boolean enableSecp256k1Algo;

	/**
	 * Utility to generate Metadata
	 */
	@Autowired
	KeymanagerUtil keymanagerUtil;

	@Autowired
	private PDFGenerator pdfGenerator;

	/**
	 * Instance for PartnerCertificateManagerService
	 */
	@Autowired
	PartnerCertificateManagerService partnerCertManagerService;

	@Autowired
	CryptomanagerUtils cryptomanagerUtil;

	@Autowired
	ECKeyStore ecKeyStore;

	private static Map<String, SignatureProvider> SIGNATURE_PROVIDER = new HashMap<>();

	AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory;

	static {
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST, new PS256SIgnatureProviderImpl());
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_RS256_SIGN_ALGO_CONST, new RS256SignatureProviderImpl());
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_ES256_SIGN_ALGO_CONST, new EC256SignatureProviderImpl());
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_ES256K_SIGN_ALGO_CONST, new EC256SignatureProviderImpl());
		SIGNATURE_PROVIDER.put(SignatureConstant.JWS_EDDSA_SIGN_ALGO_CONST, new Ed25519SignatureProviderImpl());
	}

	private static Map<String, String> JWT_SIGNATURE_ALGO_IDENT = new HashMap<>();
	static {
		JWT_SIGNATURE_ALGO_IDENT.put(SignatureConstant.BLANK, AlgorithmIdentifiers.RSA_USING_SHA256);
		JWT_SIGNATURE_ALGO_IDENT.put(SignatureConstant.REF_ID_SIGN_CONST, AlgorithmIdentifiers.RSA_USING_SHA256);
		JWT_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name(), AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256);
		JWT_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name(), AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
		JWT_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.ED25519_SIGN.name(), AlgorithmIdentifiers.EDDSA);
	}

	@PostConstruct
	public void init() {
		KeyGeneratorUtils.loadClazz();
		if (enableSecp256k1Algo) {
			AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory = 
				AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory();
			jwsAlgorithmFactory.registerAlgorithm(new EcdsaSECP256K1UsingSha256());
		}
	}

	@Override
	public SignatureResponse sign(SignRequestDto signRequestDto) {
		SignatureRequestDto signatureRequestDto = new SignatureRequestDto();
		signatureRequestDto.setApplicationId(signApplicationid);
		signatureRequestDto.setReferenceId(signRefid);
		signatureRequestDto.setData(signRequestDto.getData());
		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		signatureRequestDto.setTimeStamp(timestamp);
		SignatureResponseDto signatureResponseDTO = sign(signatureRequestDto);
		return new SignatureResponse(signatureResponseDTO.getData(), DateUtils.convertUTCToLocalDateTime(timestamp));
	}

	private SignatureResponseDto sign(SignatureRequestDto signatureRequestDto) {
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(
				signatureRequestDto.getApplicationId(), Optional.of(signatureRequestDto.getReferenceId()),
				signatureRequestDto.getTimeStamp());
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils.parseUTCToDate(signatureRequestDto.getTimeStamp()));
		String encryptedSignedData = null;
		if (certificateResponse.getCertificateEntry() != null) {
			encryptedSignedData = cryptoCore.sign(signatureRequestDto.getData().getBytes(),
					certificateResponse.getCertificateEntry().getPrivateKey());
		}
		return new SignatureResponseDto(encryptedSignedData);
	}

	@Override
	public ValidatorResponseDto validate(TimestampRequestDto timestampRequestDto) {

		PublicKeyResponse<String> publicKeyResponse = keymanagerService.getSignPublicKey(signApplicationid,
				DateUtils.formatToISOString(timestampRequestDto.getTimestamp()), Optional.of(signRefid));
		boolean status;
		try {
			PublicKey publicKey = KeyFactory.getInstance(asymmetricAlgorithmName)
					.generatePublic(new X509EncodedKeySpec(CryptoUtil.decodeURLSafeBase64(publicKeyResponse.getPublicKey())));
			status = cryptoCore.verifySignature(timestampRequestDto.getData().getBytes(),
					timestampRequestDto.getSignature(), publicKey);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException exception) {
			throw new PublicKeyParseException(SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(),
					exception.getMessage(), exception);
		}

		if (status) {
			ValidatorResponseDto response = new ValidatorResponseDto();
			response.setMessage(SignatureConstant.VALIDATION_SUCCESSFUL);
			response.setStatus(SignatureConstant.SUCCESS);
			return response;
		} else {
			throw new SignatureFailureException(SignatureErrorCode.NOT_VALID.getErrorCode(),
					SignatureErrorCode.NOT_VALID.getErrorMessage(), null);
		}
	}

	@Override
	public SignatureResponseDto signPDF(PDFSignatureRequestDto request) {
		SignatureCertificate signatureCertificate = keymanagerService.getSignatureCertificate(
				request.getApplicationId(), Optional.of(request.getReferenceId()), request.getTimeStamp());
		LOGGER.debug(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
				"Signature fetched from hsm " + signatureCertificate);
		Rectangle rectangle = new Rectangle(request.getLowerLeftX(), request.getLowerLeftY(), request.getUpperRightX(),
				request.getUpperRightY());
		OutputStream outputStream;
		try {
			String providerName = signatureCertificate.getProviderName();
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
					" Keystore Provider Name found: " + providerName);

			/* Arrays.stream(Security.getProviders()).forEach(x -> {
				LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
						"provider name " + x.getName());
				LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
						"provider info " + x.getInfo());
			});
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
					"all providers "); */
			outputStream = pdfGenerator.signAndEncryptPDF(CryptoUtil.decodeBase64(request.getData()), rectangle,
					request.getReason(), request.getPageNumber(), Security.getProvider(providerName),
					signatureCertificate.getCertificateEntry(), request.getPassword());
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
					"Completed PDF Signing.");
		} catch (IOException | GeneralSecurityException e) {
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorCode(),
					KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorMessage() + " " + e.getMessage());
		}
		SignatureResponseDto signatureResponseDto = new SignatureResponseDto();
		signatureResponseDto.setData(CryptoUtil.encodeToURLSafeBase64(((ByteArrayOutputStream) outputStream).toByteArray()));
		return signatureResponseDto;
	}

	@Override
	public JWTSignatureResponseDto jwtSign(JWTSignatureRequestDto jwtSignRequestDto) {
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Request.");

		boolean hasAcccess = cryptomanagerUtil.hasKeyAccess(jwtSignRequestDto.getApplicationId());
		if (!hasAcccess) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
						"Signing Data is not allowed for the authenticated user for the provided application id. " +
						" App Id: " + jwtSignRequestDto.getApplicationId());
			throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
				SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
		}

		String reqDataToSign = jwtSignRequestDto.getDataToSign();
		if (!SignatureUtil.isDataValid(reqDataToSign)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_INPUT.getErrorMessage());
		}

		String decodedDataToSign = new String(CryptoUtil.decodeURLSafeBase64(reqDataToSign));
		if (confValidateJson && !SignatureUtil.isJsonValid(decodedDataToSign)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign is invalid JSON.");
			throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
					SignatureErrorCode.INVALID_JSON.getErrorMessage());
		}

		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		String applicationId = jwtSignRequestDto.getApplicationId();
		String referenceId = jwtSignRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludePayload());
		boolean includeCertificate = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludeCertificate());
		boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludeCertHash());
		String certificateUrl = SignatureUtil.isDataValid(
								jwtSignRequestDto.getCertificateUrl()) ? jwtSignRequestDto.getCertificateUrl(): null;

		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
				Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils.parseUTCToDate(timestamp));
		String signedData = sign(decodedDataToSign, certificateResponse, includePayload, includeCertificate,
				includeCertHash, certificateUrl, referenceId);
		JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
		responseDto.setJwtSignedData(signedData);
		responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Request - Completed");

		return responseDto;
	}

	private String sign(String dataToSign, SignatureCertificate certificateResponse, boolean includePayload,
			boolean includeCertificate, boolean includeCertHash, String certificateUrl, String referenceId) {
		
		JsonWebSignature jwSign = new JsonWebSignature();
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
		if (includeCertificate)
			jwSign.setCertificateChainHeaderValue(new X509Certificate[] { x509Certificate });

		if (includeCertHash)
			jwSign.setX509CertSha256ThumbprintHeaderValue(x509Certificate);

		if (Objects.nonNull(certificateUrl))
			jwSign.setHeader("x5u", certificateUrl);
		
		String keyId = SignatureUtil.convertHexToBase64(certificateResponse.getUniqueIdentifier());
		if (includeKeyId && Objects.nonNull(keyId))
			jwSign.setKeyIdHeaderValue(keyId);

		jwSign.setPayload(dataToSign);
		String algoString = JWT_SIGNATURE_ALGO_IDENT.get(referenceId);
		if (!KeyReferenceIdConsts.ED25519_SIGN.name().equals(referenceId)) {
			ProviderContext provContext = new ProviderContext();
			provContext.getSuppliedKeyProviderContext().setSignatureProvider(ecKeyStore.getKeystoreProviderName());
			jwSign.setProviderContext(provContext);
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"Supported Signature Algorithm: " + 
				AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory().getSupportedAlgorithms());
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"Signature Algorithm for the input RefId: " + algoString);
		
		jwSign.setAlgorithmHeaderValue(algoString);
		jwSign.setKey(privateKey);
		jwSign.setDoKeyValidation(false);
		
		try {
			if (includePayload)
				return jwSign.getCompactSerialization();

			return jwSign.getDetachedContentCompactSerialization();
		} catch (JoseException e) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Error occurred while Signing Data.", e);
			throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(),
					SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
		}
	}

	public JWTSignatureVerifyResponseDto jwtVerify(JWTSignatureVerifyRequestDto jwtVerifyRequestDto) {
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request.");
		String signedData = jwtVerifyRequestDto.getJwtSignatureData();
		if (!SignatureUtil.isDataValid(signedData)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Signed Data value is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_INPUT.getErrorMessage());
		}

		String encodedActualData = SignatureUtil.isDataValid(jwtVerifyRequestDto.getActualData())
									? jwtVerifyRequestDto.getActualData() : null;

		String reqCertData = SignatureUtil.isDataValid(jwtVerifyRequestDto.getCertificateData())
				? jwtVerifyRequestDto.getCertificateData(): null;
		String applicationId = jwtVerifyRequestDto.getApplicationId();
		String referenceId = jwtVerifyRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		String[] jwtTokens = signedData.split(SignatureConstant.PERIOD, -1);

		boolean signatureValid = false;
		Certificate certToVerify = certificateExistsInHeader(jwtTokens[0]);
		if (Objects.nonNull(certToVerify)){
			signatureValid = verifySignature(jwtTokens, encodedActualData, certToVerify);
		} else {
			Certificate reqCertToVerify = getCertificateToVerify(reqCertData, applicationId, referenceId);
			signatureValid = verifySignature(jwtTokens, encodedActualData, reqCertToVerify);
		}

		JWTSignatureVerifyResponseDto responseDto = new JWTSignatureVerifyResponseDto();
		responseDto.setSignatureValid(signatureValid);
		responseDto.setMessage(signatureValid ? SignatureConstant.VALIDATION_SUCCESSFUL : SignatureConstant.VALIDATION_FAILED);
		responseDto.setTrustValid(validateTrust(jwtVerifyRequestDto, certToVerify, reqCertData));
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request - Completed.");
		return responseDto;
	}

	private Certificate getCertificateToVerify(String reqCertData, String applicationId, String referenceId) {
		// 2nd precedence to consider certificate to use in signature verification (Certificate Data provided in request).
		if (reqCertData != null)
			return keymanagerUtil.convertToCertificate(reqCertData);
		
		// 3rd precedence to consider certificate to use in signature verification. (based on AppId & RefId)
		KeyPairGenerateResponseDto certificateResponse = keymanagerService.getCertificate(applicationId,
				Optional.of(referenceId));
		return keymanagerUtil.convertToCertificate(certificateResponse.getCertificate());
	}
	
	@SuppressWarnings("unchecked")
	private Certificate certificateExistsInHeader(String jwtHeader) {
		String jwtTokenHeader = new String(CryptoUtil.decodeURLSafeBase64(jwtHeader));
		Map<String, Object> jwtTokenHeadersMap = null;
		try {
			jwtTokenHeadersMap = JsonUtils.jsonStringToJavaMap(jwtTokenHeader);
		} catch (JsonParseException | JsonMappingException | io.mosip.kernel.core.exception.IOException e) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Signed Data value is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorMessage());
		} 
		// 1st precedence to consider certificate to use in signature verification (JWT Header).
		if (jwtTokenHeadersMap.containsKey(SignatureConstant.JWT_HEADER_CERT_KEY)) {
			LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Certificate found in JWT Header.");
			List<String> certList = (List<String>) jwtTokenHeadersMap.get(SignatureConstant.JWT_HEADER_CERT_KEY);
			return keymanagerUtil.convertToCertificate(Base64.decodeBase64(certList.get(0)));
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Certificate not found in JWT Header.");
		return null;
	}

	private boolean verifySignature(String[] jwtTokens, String actualData, Certificate certToVerify) {
		JsonWebSignature jws = new JsonWebSignature();
		try {
			X509Certificate x509CertToVerify = (X509Certificate) certToVerify;
			boolean validCert = SignatureUtil.isCertificateDatesValid(x509CertToVerify);
			if (!validCert) {
				LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Error certificate dates are not valid.");
					throw new CertificateNotValidException(SignatureErrorCode.CERT_NOT_VALID.getErrorCode(),
								SignatureErrorCode.CERT_NOT_VALID.getErrorMessage());
			}

			String keyAlgorithm = x509CertToVerify.getPublicKey().getAlgorithm();
			PublicKey publicKey = null;
			if (keyAlgorithm.equals(KeymanagerConstant.EDDSA_KEY_TYPE)) {
				LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Found Ed25519 Certificate for Signature verification.");
				publicKey = KeyGeneratorUtils.createPublicKey(KeymanagerConstant.ED25519_KEY_TYPE, 
							x509CertToVerify.getPublicKey().getEncoded());
				LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
							"Supported Signature Algorithm: " + 
					AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory().getSupportedAlgorithms());
			} else {
				LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"KeyStore Provider Name:" + ecKeyStore.getKeystoreProviderName());
				if (!ecKeyStore.getKeystoreProviderName().equals(
						io.mosip.kernel.keymanager.hsm.constant.KeymanagerConstant.KEYSTORE_TYPE_OFFLINE)) {
					ProviderContext provContext = new ProviderContext();
					provContext.getSuppliedKeyProviderContext().setSignatureProvider(ecKeyStore.getKeystoreProviderName());
					jws.setProviderContext(provContext);
				}
				publicKey = certToVerify.getPublicKey();
			}
						
			if (Objects.nonNull(actualData))
				jwtTokens[1] = actualData;

			jws.setCompactSerialization(CompactSerializer.serialize(jwtTokens));
			jws.setDoKeyValidation(false);
			if (Objects.nonNull(publicKey))
				jws.setKey(publicKey);

			return jws.verifySignature();
		} catch (JoseException e) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Signed Data value is invalid.", e);
			throw new SignatureFailureException(SignatureErrorCode.VERIFY_ERROR.getErrorCode(),
									SignatureErrorCode.VERIFY_ERROR.getErrorMessage(), e);
		}
	}

	private String validateTrust(JWTSignatureVerifyRequestDto jwtVerifyRequestDto, Certificate headerCertificate, String reqCertData) {
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request - Trust Validation.");
		boolean validateTrust = SignatureUtil.isIncludeAttrsValid(jwtVerifyRequestDto.getValidateTrust());
		if (!validateTrust) {
			return SignatureConstant.TRUST_NOT_VERIFIED;
		}
		
		String domain = jwtVerifyRequestDto.getDomain();
		if(!SignatureUtil.isDataValid(domain))
			return SignatureConstant.TRUST_NOT_VERIFIED_NO_DOMAIN;
		
		String certData = null;
		if (Objects.nonNull(headerCertificate)) {
			certData = keymanagerUtil.getPEMFormatedData(headerCertificate);
		}
		String trustCertData = certData == null ? reqCertData : certData;

		if (trustCertData == null) 
			return SignatureConstant.TRUST_NOT_VERIFIED;
		
		CertificateTrustRequestDto trustRequestDto = new CertificateTrustRequestDto();
		trustRequestDto.setCertificateData(trustCertData);
		trustRequestDto.setPartnerDomain(domain);
		CertificateTrustResponeDto responseDto = partnerCertManagerService.verifyCertificateTrust(trustRequestDto);
		
		if (responseDto.getStatus()){
			return SignatureConstant.TRUST_VALID;
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request - Trust Validation - Completed.");
		return SignatureConstant.TRUST_NOT_VALID;
	}

	@Override
	public JWTSignatureResponseDto jwsSign(JWSSignatureRequestDto jwsSignRequestDto) {
		// TODO Code is duplicated from jwtSign method. Duplicate code will be removed later when VC verification is implement.
		// Code duplicated because now does not want to make any change to existing code which is well tested.
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
				"JWS Signature Request.");

		boolean hasAcccess = cryptomanagerUtil.hasKeyAccess(jwsSignRequestDto.getApplicationId());
		if (!hasAcccess) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
							"Signing Data is not allowed for the authenticated user for the provided application id.");
			throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
				SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
		}

		String reqDataToSign = jwsSignRequestDto.getDataToSign();
		if (!SignatureUtil.isDataValid(reqDataToSign)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_INPUT.getErrorMessage());
		}

		Boolean validateJson = jwsSignRequestDto.getValidateJson();
		byte[] dataToSign = CryptoUtil.decodeURLSafeBase64(reqDataToSign);
		if (validateJson && !SignatureUtil.isJsonValid(new String(dataToSign))) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign value is invalid JSON.");
			throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
					SignatureErrorCode.INVALID_JSON.getErrorMessage());
		}

		String timestamp = DateUtils.getUTCCurrentDateTimeString();
		String applicationId = jwsSignRequestDto.getApplicationId();
		String referenceId = jwsSignRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludePayload());
		boolean includeCertificate = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertificate());
		boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertHash());
		String certificateUrl = SignatureUtil.isDataValid(
								jwsSignRequestDto.getCertificateUrl()) ? jwsSignRequestDto.getCertificateUrl(): null;
		boolean b64JWSHeaderParam = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getB64JWSHeaderParam());
		String signAlgorithm = SignatureUtil.isDataValid(jwsSignRequestDto.getSignAlgorithm()) ? 
									jwsSignRequestDto.getSignAlgorithm(): SignatureConstant.JWS_PS256_SIGN_ALGO_CONST;
		
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
									Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
									DateUtils.parseUTCToDate(timestamp));
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
		String providerName = certificateResponse.getProviderName();
		String uniqueIdentifier = certificateResponse.getUniqueIdentifier();
		JWSHeader jwsHeader = SignatureUtil.getJWSHeader(signAlgorithm, b64JWSHeaderParam, includeCertificate, 
					includeCertHash, certificateUrl, x509Certificate, uniqueIdentifier, includeKeyId);
		
		if (b64JWSHeaderParam) {
			dataToSign = reqDataToSign.getBytes(StandardCharsets.UTF_8);
		}
		byte[] jwsSignData = SignatureUtil.buildSignData(jwsHeader, dataToSign);
		
		SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get(signAlgorithm);
		if (Objects.isNull(signatureProvider)) {
			signatureProvider = SIGNATURE_PROVIDER.get(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST);
		}
		 
		String signature = signatureProvider.sign(privateKey, jwsSignData, providerName);

		StringBuilder signedData = new StringBuilder().append(jwsHeader.toBase64URL().toString())
														 .append(".")
														 .append(includePayload? reqDataToSign: "")
														 .append(".")
														 .append(signature);
														 
		JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
		responseDto.setJwtSignedData(signedData.toString());
		responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
		if (referenceId.equals(KeyReferenceIdConsts.ED25519_SIGN.name())) {
			LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"Found Ed25519 Key for Signature, clearing the Key from memory.");
			privateKey = null;
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
				"JWS Signature Request - Completed.");
		return responseDto;
	}

	public static class EcdsaSECP256K1UsingSha256 extends EcdsaUsingShaAlgorithm
    {
        public EcdsaSECP256K1UsingSha256() {
            super(AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256, 
					"SHA256withECDSA", EllipticCurves.SECP_256K1, 64);
        }

        @Override
        public boolean isAvailable(){
            return true;
        }
    }
}
