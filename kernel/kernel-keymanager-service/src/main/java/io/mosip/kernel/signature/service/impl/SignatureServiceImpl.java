package io.mosip.kernel.signature.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.crypto.SecretKey;

import io.ipfs.multibase.Multibase;
import io.mosip.kernel.core.util.DateUtils2;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;
import io.mosip.kernel.signature.dto.*;
import io.mosip.kernel.signature.service.SignatureServicev2;
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
import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
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
public class SignatureServiceImpl implements SignatureService, SignatureServicev2 {

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

	@Value("${mosip.kernel.keymanager.signature.kid.prepend:}")
	private String kidPrepend;

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

	@Autowired
	SignatureUtil signatureUtil;

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

    // ---- FAST PATH CACHES ----
    private final ConcurrentMap<String, PublicKey> pubKeyCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, X509Certificate> certCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> jwsHeaderCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Provider> providerCache = new ConcurrentHashMap<>();
    private static final long TRUST_TTL_MS = 5 * 60 * 1000; // 5 minutes
    private static final class BoolWithTs { final boolean v; final long ts; BoolWithTs(boolean v,long ts){this.v=v;this.ts=ts;} }
    private final ConcurrentMap<String, BoolWithTs> trustCache = new ConcurrentHashMap<>();

    // Keep lightweight decoders & factories thread-local
    private static final ThreadLocal<java.security.KeyFactory> KF_RSA =

            ThreadLocal.withInitial(() -> { try { return KeyFactory.getInstance("RSA"); } catch (Exception e) { throw new RuntimeException(e); }});
    private static final ThreadLocal<java.security.KeyFactory> KF_EC =
            ThreadLocal.withInitial(() -> { try { return KeyFactory.getInstance("EC"); } catch (Exception e) { throw new RuntimeException(e); }});
    private static final ThreadLocal<java.security.KeyFactory> KF_ED =
            ThreadLocal.withInitial(() -> { try { return KeyFactory.getInstance("Ed25519"); } catch (Exception e) { throw new RuntimeException(e); }});

    private static final ThreadLocal<java.security.MessageDigest> MD_SHA256 =
            ThreadLocal.withInitial(() -> {
                try { return java.security.MessageDigest.getInstance("SHA-256"); }
                catch (java.security.NoSuchAlgorithmException e) { throw new RuntimeException(e); }
            });
    private static final ThreadLocal<java.util.Base64.Decoder> B64_DEC = ThreadLocal.withInitial(java.util.Base64::getDecoder);
    private static final ThreadLocal<java.util.Base64.Encoder> B64_ENC = ThreadLocal.withInitial(java.util.Base64::getEncoder);

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
		String timestamp = DateUtils2.getUTCCurrentDateTimeString();
		signatureRequestDto.setTimeStamp(timestamp);
		SignatureResponseDto signatureResponseDTO = sign(signatureRequestDto);
		return new SignatureResponse(signatureResponseDTO.getData(), DateUtils2.convertUTCToLocalDateTime(timestamp));
	}

	private SignatureResponseDto sign(SignatureRequestDto signatureRequestDto) {
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(
				signatureRequestDto.getApplicationId(), Optional.of(signatureRequestDto.getReferenceId()),
				signatureRequestDto.getTimeStamp());
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils2.parseUTCToDate(signatureRequestDto.getTimeStamp()));
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
				DateUtils2.formatToISOString(timestampRequestDto.getTimestamp()), Optional.of(signRefid));
		boolean status;
		try {
            final String algo  = asymmetricAlgorithmName;           // e.g., "RSA", "EC", "Ed25519"
            final String pkB64 = publicKeyResponse.getPublicKey();             // URL-safe Base64 SPKI
            final String cacheKey = algo + '|' + pkB64;             // stable cache key

            // 2) Decode + cache PublicKey (avoid repeated KeyFactory/decoding)
            final PublicKey publicKey;
            try {
                publicKey = pubKeyCache.computeIfAbsent(cacheKey, k -> {
                    try { return decodePublicKey(algo, pkB64); }
                    catch (GeneralSecurityException e) { throw new RuntimeException(e); }
                });
            } catch (RuntimeException re) {
                Throwable cause = re.getCause();
                if (cause instanceof InvalidKeySpecException || cause instanceof NoSuchAlgorithmException || cause instanceof GeneralSecurityException) {
                    throw new PublicKeyParseException(SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(),
                            cause.getMessage(), (Exception) cause);
                }
                throw re; // unexpected
            }

            status = cryptoCore.verifySignature(timestampRequestDto.getData().getBytes(),
                    timestampRequestDto.getSignature(), publicKey);
        } catch (Exception exception) {
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
		final SignatureCertificate signatureCertificate = keymanagerService.getSignatureCertificate(
				request.getApplicationId(), Optional.of(request.getReferenceId()), request.getTimeStamp());
		LOGGER.debug(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
				"Signature fetched from hsm " + signatureCertificate);
		final Rectangle rectangle = new Rectangle(request.getLowerLeftX(), request.getLowerLeftY(), request.getUpperRightX(),
				request.getUpperRightY());
		try {
            final String providerName = signatureCertificate.getProviderName();
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
                    " Keystore Provider Name found: " + providerName);

            final java.security.Provider provider = (providerName == null || providerName.isBlank())
                    ? null
                    : providerCache.computeIfAbsent(providerName, java.security.Security::getProvider);

            final byte[] pdfBytes = CryptoUtil.decodeBase64(request.getData());

            // Sign & encrypt
            final OutputStream out = pdfGenerator.signAndEncryptPDF(pdfBytes, rectangle, request.getReason(),
                    request.getPageNumber(), provider, // may be null → default provider path
                    signatureCertificate.getCertificateEntry(), request.getPassword());

            if (!(out instanceof ByteArrayOutputStream)) {
                try { out.close(); } catch (IOException ignore) {}
                throw new KeymanagerServiceException(
                        KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorCode(),
                        "Unsupported OutputStream from pdfGenerator: " + out.getClass().getName()
                                + ". Expecting ByteArrayOutputStream or an API that writes to a provided OutputStream.");
            }

            // Extract bytes efficiently
            byte[] signedBytes = ((ByteArrayOutputStream) out).toByteArray();

            // Build response (URL-safe Base64)
            SignatureResponseDto resp = new SignatureResponseDto();
            resp.setData(CryptoUtil.encodeToURLSafeBase64(signedBytes));
            LOGGER.debug(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
                    "Completed PDF signing.");
            return resp;
        } catch (IOException | GeneralSecurityException e) {
            throw new KeymanagerServiceException(KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorCode(),
                    KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorMessage() + " " + e.getMessage());
        }
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

		final String decodedDataToSign = new String(CryptoUtil.decodeURLSafeBase64(reqDataToSign));
		if (confValidateJson && !SignatureUtil.isJsonValid(decodedDataToSign)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign is invalid JSON.");
			throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
					SignatureErrorCode.INVALID_JSON.getErrorMessage());
		}

		String timestamp = DateUtils2.getUTCCurrentDateTimeString();
		String applicationId = jwtSignRequestDto.getApplicationId();
		String referenceId = jwtSignRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		final boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludePayload());
		final boolean includeCertificate = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludeCertificate());
		final boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludeCertHash());
		final String certificateUrl = SignatureUtil.isDataValid(
								jwtSignRequestDto.getCertificateUrl()) ? jwtSignRequestDto.getCertificateUrl(): null;

		final SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
				Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils2.parseUTCToDate(timestamp));
		String signedData = sign(decodedDataToSign, certificateResponse, includePayload, includeCertificate,
				includeCertHash, certificateUrl, referenceId);
		JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
		responseDto.setJwtSignedData(signedData);
		responseDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Request - Completed");

		return responseDto;
	}

	private String sign(String dataToSign, SignatureCertificate certificateResponse, boolean includePayload,
			boolean includeCertificate, boolean includeCertHash, String certificateUrl, String referenceId) {

        PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
        X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];

        // kid prefix may depend on payload issuer (same as your original logic)
        String kidPrefix = kidPrepend;
        if (kidPrepend.equalsIgnoreCase(SignatureConstant.KEY_ID_PREFIX)) {
            kidPrefix = SignatureUtil.getIssuerFromPayload(dataToSign)
                    .concat(SignatureConstant.KEY_ID_SEPARATOR);
        }
        final String keyId = SignatureUtil.convertHexToBase64(certificateResponse.getUniqueIdentifier());

        // Alg selection from referenceId (same defaults)
        String algoString = JWT_SIGNATURE_ALGO_IDENT.get(referenceId);
        if (algoString == null || algoString.isBlank()) {
            algoString = AlgorithmIdentifiers.RSA_USING_SHA256;
        }

        // --- Header caching: build a stable cache key for this exact header shape ---
        final String certIdentity = x509Certificate.getSerialNumber() + ":" +
                x509Certificate.getIssuerX500Principal().getName();
        final String kidValue = (includeKeyId && keyId != null) ? kidPrefix + keyId : "";
        final String hdrKey = cacheKey("HDR", referenceId,
                Boolean.toString(includeCertificate),
                Boolean.toString(includeCertHash),
                certificateUrl == null ? "" : certificateUrl,
                Boolean.toString(includeKeyId),
                kidValue,
                algoString,
                certIdentity);

        // Try to reuse a precomputed protected header JSON
        String headerJson = jwsHeaderCache.get(hdrKey);
        if (headerJson == null) {
            JsonWebSignature headerBuilder = new JsonWebSignature();
            headerBuilder.setAlgorithmHeaderValue(algoString);
            if (includeCertificate) {
                headerBuilder.setCertificateChainHeaderValue(new X509Certificate[]{ x509Certificate });
            }
            if (includeCertHash) {
                headerBuilder.setX509CertSha256ThumbprintHeaderValue(x509Certificate);
            }
            if (certificateUrl != null) {
                headerBuilder.setHeader("x5u", certificateUrl);
            }
            if (includeKeyId && keyId != null) {
                headerBuilder.setKeyIdHeaderValue(kidPrefix.concat(keyId));
            }
            headerJson = headerBuilder.getHeaders().getFullHeaderAsJsonString();
            jwsHeaderCache.putIfAbsent(hdrKey, headerJson);
        }

        // Build + sign using the cached header
        JsonWebSignature jwSign = new JsonWebSignature();
        try {
            jwSign.getHeaders().setFullHeaderAsJsonString(headerJson);
        } catch (JoseException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                    "Error occurred while Signing Data.", e);
            throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(),
                    SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
        }

        // Only set provider when needed to avoid provider lookups on every call
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

        jwSign.setKey(privateKey);
        jwSign.setDoKeyValidation(false);
        jwSign.setPayload(dataToSign);

        //jwSign.setAlgorithmHeaderValue(algoString);

        try {
            return includePayload
                    ? jwSign.getCompactSerialization()
                    : jwSign.getDetachedContentCompactSerialization();
		} catch (JoseException e) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Error occurred while Signing Data.", e);
			throw new SignatureFailureException(SignatureErrorCode.SIGN_ERROR.getErrorCode(),
					SignatureErrorCode.SIGN_ERROR.getErrorMessage(), e);
		}
	}

	@Override
	public JWTSignatureVerifyResponseDto jwtVerify(JWTSignatureVerifyRequestDto jwtVerifyRequestDto) {
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request.");
		final String signedData = jwtVerifyRequestDto.getJwtSignatureData();
		if (!SignatureUtil.isDataValid(signedData)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided Signed Data value is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_INPUT.getErrorMessage());
		}

		final String encodedActualData = SignatureUtil.isDataValid(jwtVerifyRequestDto.getActualData())
									? jwtVerifyRequestDto.getActualData() : null;

		String applicationId = jwtVerifyRequestDto.getApplicationId();
		String referenceId = jwtVerifyRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		String[] jwtTokens = signedData.split(SignatureConstant.PERIOD, -1);

		Certificate certFromHeader = certificateExistsInHeader(jwtTokens[0]);
        // 2nd precedence: request cert; 3rd: keymanager (app/ref)
        final String reqCertData = SignatureUtil.isDataValid(jwtVerifyRequestDto.getCertificateData())
                ? jwtVerifyRequestDto.getCertificateData() : null;
        final Certificate certToVerify = (certFromHeader != null)
                ? certFromHeader
                : getCertificateToVerify(reqCertData, applicationId, referenceId);

        // Verify signature (verifySignature handles detached payload when encodedActualData != null)
        final boolean signatureValid = verifySignature(jwtTokens, encodedActualData, certToVerify);

		JWTSignatureVerifyResponseDto responseDto = new JWTSignatureVerifyResponseDto();
		responseDto.setSignatureValid(signatureValid);
		responseDto.setMessage(signatureValid ? SignatureConstant.VALIDATION_SUCCESSFUL : SignatureConstant.VALIDATION_FAILED);
		responseDto.setTrustValid(validateTrust(jwtVerifyRequestDto, certToVerify));
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
        try {
            String headerJson = new String(CryptoUtil.decodeURLSafeBase64(jwtHeader), StandardCharsets.UTF_8);

            org.jose4j.jwx.Headers headers = new org.jose4j.jwx.Headers();
            headers.setFullHeaderAsJsonString(headerJson);

            // 0) Try cache by x5t#S256 if present
            String x5tS256 = headers.getStringHeaderValue("x5t#S256");
            if (x5tS256 != null) {
                X509Certificate cached = certCache.get(cacheKey("X5T", x5tS256));
                if (cached != null) {
                    LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                            "Certificate found via x5t#S256 cache.");
                    return cached;
                }
            }
            // 1st precedence: certificate from JWT header ("x5c")
            final Object x5cObj = headers.getObjectHeaderValue(SignatureConstant.JWT_HEADER_CERT_KEY); // "x5c"
            if (x5cObj == null) {
                LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                        "Certificate not found in JWT Header.");
                return null;
            }
            // Standard: array of base64 DER certs; Tolerate: single string
            String firstCertB64 = null;
            if (x5cObj instanceof List<?> list) {
                if (!list.isEmpty() && list.get(0) instanceof String) {
                    firstCertB64 = (String) list.get(0);
                }
            } else if (x5cObj instanceof String) {
                firstCertB64 = (String) x5cObj;
            }

            if (firstCertB64 == null || firstCertB64.isEmpty()) {
                LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                        "Certificate not found in JWT Header.");
                return null;
            }

            // Build X509Certificate from DER
            byte[] der = B64_DEC.get().decode(firstCertB64);
            Certificate cert = keymanagerUtil.convertToCertificate(der);
            if (cert != null) {
                // 2) Seed cache by x5t#S256 (from header or computed)
                if (x5tS256 == null && cert instanceof X509Certificate) {
                    x5tS256 = computeX5tS256((X509Certificate) cert);
                }
                if (x5tS256 != null) cacheCert(cacheKey("X5T", x5tS256), cert);

                LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                        "Certificate found in JWT Header.");
                return cert;
            }
            LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                    "Certificate not found in JWT Header.");
            return null;
        } catch (JoseException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                    "Provided Signed Data value is invalid.");
            throw new RequestException(SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorCode(),
                    SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorMessage());
        }  catch (Exception e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                    "Error parsing JWT header.", e);
            throw new RequestException(SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorCode(),
                    SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorMessage());
        }
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

	private String validateTrust(JWTSignatureVerifyRequestDto jwtVerifyRequestDto, Certificate reqCertToVerify) {
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request - Trust Validation.");
		boolean validateTrust = SignatureUtil.isIncludeAttrsValid(jwtVerifyRequestDto.getValidateTrust());
		if (!validateTrust) {
			return SignatureConstant.TRUST_NOT_VERIFIED;
		}
		
		String domain = jwtVerifyRequestDto.getDomain();
		if(!SignatureUtil.isDataValid(domain))
			return SignatureConstant.TRUST_NOT_VERIFIED_NO_DOMAIN;
		
		String trustCertData = null;
		if (reqCertToVerify != null) {
			trustCertData = keymanagerUtil.getPEMFormatedData(reqCertToVerify);
		}

		if (!SignatureUtil.isDataValid(trustCertData))
			return SignatureConstant.TRUST_NOT_VERIFIED;
		
		CertificateTrustRequestDto trustRequestDto = new CertificateTrustRequestDto();
		trustRequestDto.setCertificateData(trustCertData);
		trustRequestDto.setPartnerDomain(domain);
		CertificateTrustResponeDto response = partnerCertManagerService.verifyCertificateTrust(trustRequestDto);

		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request - Trust Validation - Completed.");
		return response.getStatus() ? SignatureConstant.TRUST_VALID : SignatureConstant.TRUST_NOT_VALID;
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

		final String reqDataToSign = jwsSignRequestDto.getDataToSign();
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

		String kidPrefix = kidPrepend;
		if (kidPrepend.equalsIgnoreCase(SignatureConstant.KEY_ID_PREFIX)) {
			kidPrefix = SignatureUtil.getIssuerFromPayload(new String(CryptoUtil.decodeURLSafeBase64(reqDataToSign))).concat(SignatureConstant.KEY_ID_SEPARATOR);
		}

		String timestamp = DateUtils2.getUTCCurrentDateTimeString();
		String applicationId = jwsSignRequestDto.getApplicationId();
		String referenceId = jwsSignRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		final boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludePayload());
		final boolean includeCertificate = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertificate());
		final boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertHash());
		final String certificateUrl = SignatureUtil.isDataValid(
								jwsSignRequestDto.getCertificateUrl()) ? jwsSignRequestDto.getCertificateUrl(): null;
		final boolean b64JWSHeaderParam = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getB64JWSHeaderParam());
		String signAlgorithm = (jwsSignRequestDto.getSignAlgorithm() == null || jwsSignRequestDto.getSignAlgorithm().isBlank()) ?
				SignatureUtil.getSignAlgorithm(referenceId) : jwsSignRequestDto.getSignAlgorithm();
		
		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
									Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
									DateUtils2.parseUTCToDate(timestamp));
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
		String providerName = certificateResponse.getProviderName();
		String uniqueIdentifier = certificateResponse.getUniqueIdentifier();
		JWSHeader jwsHeader = SignatureUtil.getJWSHeader(signAlgorithm, b64JWSHeaderParam, includeCertificate, 
					includeCertHash, certificateUrl, x509Certificate, uniqueIdentifier, includeKeyId, kidPrefix);
		
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
		responseDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
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

	@Override
	public SignResponseDto signv2(SignRequestDtoV2 signatureReq) {
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.RAW_SIGN, SignatureConstant.BLANK,
				"Raw Sign Signature Request.");
		String applicationId = signatureReq.getApplicationId();
		String referenceId = signatureReq.getReferenceId();
		boolean hasAcccess = cryptomanagerUtil.hasKeyAccess(applicationId);
		String reqDataToSign = signatureReq.getDataToSign();
		if (!hasAcccess) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.RAW_SIGN, SignatureConstant.BLANK,
					"Signing Data is not allowed for the authenticated user for the provided application id.");
			throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
					SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
		}

		if (!SignatureUtil.isDataValid(reqDataToSign)) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.RAW_SIGN, SignatureConstant.BLANK,
					"Provided Data to sign is invalid.");
			throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
					SignatureErrorCode.INVALID_INPUT.getErrorMessage());
		}
		byte[] dataToSign = CryptoUtil.decodeURLSafeBase64(reqDataToSign);
		String timestamp = DateUtils2.getUTCCurrentDateTimeString();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}
		String signAlgorithm = SignatureUtil.isDataValid(signatureReq.getSignAlgorithm()) ?
				signatureReq.getSignAlgorithm() : SignatureConstant.JWS_PS256_SIGN_ALGO_CONST;

		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
				Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils2.parseUTCToDate(timestamp));
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		certificateResponse.getCertificateEntry().getChain();
		String providerName = certificateResponse.getProviderName();
		SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get(signAlgorithm);
		if (Objects.isNull(signatureProvider)) {
			signatureProvider = SIGNATURE_PROVIDER.get(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST);
		}
		String signature = signatureProvider.sign(privateKey, dataToSign, providerName);
		SignResponseDto signedDataResponse = new SignResponseDto();
		signedDataResponse.setTimestamp(DateUtils2.getUTCCurrentDateTime());
		String encodingFromat = (signatureReq.getResponseEncodingFormat() == null || signatureReq.getResponseEncodingFormat().isBlank()) ? SignatureConstant.BASE58BTC : signatureReq.getResponseEncodingFormat();
		switch (encodingFromat) {
			case SignatureConstant.BASE64URL:
				signedDataResponse.setSignature(signature);
				break;
			case SignatureConstant.BASE58BTC:
                byte[] data = java.util.Base64.getUrlDecoder().decode(signature);
				signedDataResponse.setSignature(
						Multibase.encode(Multibase.Base.Base58BTC, data));
				break;
			default:
				throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_FORMAT_ERROR.getErrorCode(),
						KeymanagerErrorConstant.INVALID_FORMAT_ERROR.getErrorMessage());
		}
		return signedDataResponse;
	}

    @Override
    public SignResponseDtoV2 rawSign(SignRequestDtoV2 signatureReq) {
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.RAW_SIGN, SignatureConstant.BLANK,
                "Raw Sign Signature Request.");
        String applicationId = signatureReq.getApplicationId();
        String referenceId = signatureReq.getReferenceId();
        boolean hasAcccess = cryptomanagerUtil.hasKeyAccess(applicationId);
        String reqDataToSign = signatureReq.getDataToSign();
        if (!hasAcccess) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.RAW_SIGN, SignatureConstant.BLANK,
                    "Signing Data is not allowed for the authenticated user for the provided application id.");
            throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
                    SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
        }

        if (!SignatureUtil.isDataValid(reqDataToSign)) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.RAW_SIGN, SignatureConstant.BLANK,
                    "Provided Data to sign is invalid.");
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                    SignatureErrorCode.INVALID_INPUT.getErrorMessage());
        }
        byte[] dataToSign = CryptoUtil.decodeURLSafeBase64(reqDataToSign);
        String timestamp = DateUtils2.getUTCCurrentDateTimeString();
        if (!keymanagerUtil.isValidApplicationId(applicationId)) {
            applicationId = signApplicationid;
            referenceId = signRefid;
        }
        String signAlgorithm = SignatureUtil.isDataValid(signatureReq.getSignAlgorithm()) ?
                signatureReq.getSignAlgorithm() : SignatureConstant.JWS_PS256_SIGN_ALGO_CONST;

        SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
                Optional.of(referenceId), timestamp);
        keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
                DateUtils2.parseUTCToDate(timestamp));
        PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
        certificateResponse.getCertificateEntry().getChain();
        String providerName = certificateResponse.getProviderName();
        SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get(signAlgorithm);
        if (Objects.isNull(signatureProvider)) {
            signatureProvider = SIGNATURE_PROVIDER.get(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST);
        }
        String signature = signatureProvider.sign(privateKey, dataToSign, providerName);
        SignResponseDtoV2 responseDto = new SignResponseDtoV2();
        responseDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
        String encodingFromat = (signatureReq.getResponseEncodingFormat() == null || signatureReq.getResponseEncodingFormat().isBlank()) ? SignatureConstant.BASE58BTC : signatureReq.getResponseEncodingFormat();
        switch (encodingFromat) {
            case SignatureConstant.BASE64URL:
                responseDto.setSignedData(signature);
                break;
            case SignatureConstant.BASE58BTC:
                byte[] data = java.util.Base64.getUrlDecoder().decode(signature);
                responseDto.setSignedData(Multibase.encode(Multibase.Base.Base58BTC, data));
                break;
            default:
                throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_FORMAT_ERROR.getErrorCode(),
                        KeymanagerErrorConstant.INVALID_FORMAT_ERROR.getErrorMessage());
        }
        responseDto.setCertificate(keymanagerUtil.getPEMFormatedData(certificateResponse.getCertificateEntry().getChain()[0]));
        responseDto.setSignatureAlgorithm(signAlgorithm);
        responseDto.setKeyId(SignatureUtil.convertHexToBase64(certificateResponse.getUniqueIdentifier()));
        return responseDto;
    }

    private static String cacheKey(String... parts) {
        return String.join("|", parts);
    }

    private PublicKey decodePublicKey(String algo, String b64Url) throws GeneralSecurityException {
        byte[] raw = B64_DEC.get().decode(b64Url);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(raw);
        return switch (algo) {
            case "RSA" -> KF_RSA.get().generatePublic(spec);
            case "EC" -> KF_EC.get().generatePublic(spec);
            case "Ed25519" -> KF_ED.get().generatePublic(spec);
            default -> KeyFactory.getInstance(algo).generatePublic(spec);
        };
    }

    // Cache X.509 certs by SHA-256 of DER (or header x5t#S256)
    private void cacheCert(String key, Certificate cert) {
        if (cert instanceof X509Certificate) {
            certCache.putIfAbsent(key, (X509Certificate) cert);
        }
    }

    private static String computeX5tS256(X509Certificate cert) {
        try {
            byte[] digest = sha256(cert.getEncoded());
            return b64NoPad(digest);
        } catch (java.security.cert.CertificateEncodingException e) {
            return null;
        }
    }

    private static byte[] sha256(byte[] input) {
        java.security.MessageDigest md = MD_SHA256.get();
        md.reset();
        md.update(input);
        return md.digest();
    }

    private static String b64NoPad(byte[] bytes) {
        return B64_ENC.get().withoutPadding().encodeToString(bytes);
    }

	@Override
	public JWTSignatureResponseDto jwtSignV2(JWTSignatureRequestDtoV2 jwtSignRequestDto) {
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

		String timestamp = DateUtils2.getUTCCurrentDateTimeString();
		String applicationId = jwtSignRequestDto.getApplicationId();
		String referenceId = jwtSignRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludePayload());
		boolean includeCertificateChain = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludeCertificateChain());
		boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwtSignRequestDto.getIncludeCertHash());
		String certificateUrl = SignatureUtil.isDataValid(
				jwtSignRequestDto.getCertificateUrl()) ? jwtSignRequestDto.getCertificateUrl(): null;

		Map<String, String> additionalHeaders = jwtSignRequestDto.getAdditionalHeaders();

		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
				Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils2.parseUTCToDate(timestamp));

		String signedData = signV2(decodedDataToSign, certificateResponse, includePayload, includeCertificateChain,
				includeCertHash, certificateUrl, referenceId, additionalHeaders);
		JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
		responseDto.setJwtSignedData(signedData);
		responseDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Request - Completed");

		return responseDto;
	}

	private String signV2(String dataToSign, SignatureCertificate certificateResponse, boolean includePayload,
						  boolean includeCertificate, boolean includeCertHash, String certificateUrl, String referenceId, Map<String, String> additionalHeaders) {

		JsonWebSignature jwSign = new JsonWebSignature();
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
		List<? extends Certificate> certificateChain = signatureUtil.getCertificateTrustChain(x509Certificate);
		if (includeCertificate) {
			X509Certificate[] certArray = certificateChain.stream()
					.filter(cert -> cert instanceof X509Certificate)
					.map(cert -> (X509Certificate) cert)
					.toArray(X509Certificate[]::new);
			jwSign.setCertificateChainHeaderValue(certArray);
		}

		if (includeCertHash)
			jwSign.setX509CertSha256ThumbprintHeaderValue(x509Certificate);

		if (Objects.nonNull(certificateUrl))
			jwSign.setHeader("x5u", certificateUrl);

		// Add additional headers skip on error
		if (additionalHeaders != null) {
			for (Map.Entry<String, String> entry : additionalHeaders.entrySet()) {
				if (!"kid".equalsIgnoreCase(entry.getKey())) {
					try {
						jwSign.setHeader(entry.getKey(), entry.getValue());
					} catch (Exception e) {
						// Log the error but skip and continue processing
						e.printStackTrace();
					}
				}
			}
		}

		String kidPrefix = kidPrepend;
		if (kidPrepend.equalsIgnoreCase(SignatureConstant.KEY_ID_PREFIX)) {
			kidPrefix = SignatureUtil.getIssuerFromPayload(dataToSign).concat(SignatureConstant.KEY_ID_SEPARATOR);
		}
		String keyId = SignatureUtil.convertHexToBase64(certificateResponse.getUniqueIdentifier());
		if (includeKeyId && Objects.nonNull(keyId)) {
			if (additionalHeaders != null && additionalHeaders.containsKey("kid")) {
				String mapKeyId = additionalHeaders.get("kid");
				if (mapKeyId.isEmpty() || mapKeyId.charAt(mapKeyId.length()-1) != SignatureConstant.KEY_ID_SEPARATOR.charAt(0)) {
					mapKeyId = mapKeyId.concat(SignatureConstant.KEY_ID_SEPARATOR);
				}
				kidPrefix = mapKeyId;
			}
			jwSign.setKeyIdHeaderValue(kidPrefix.concat(keyId));
		}

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

	@Override
	public JWTSignatureResponseDto jwsSignV2(JWSSignatureRequestDtoV2 jwsSignRequestDto) {
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

		String kidPrefix = kidPrepend;
		if (kidPrepend.equalsIgnoreCase(SignatureConstant.KEY_ID_PREFIX)) {
			kidPrefix = SignatureUtil.getIssuerFromPayload(new String(CryptoUtil.decodeURLSafeBase64(reqDataToSign))).concat(SignatureConstant.KEY_ID_SEPARATOR);
		}

		String timestamp = DateUtils2.getUTCCurrentDateTimeString();
		String applicationId = jwsSignRequestDto.getApplicationId();
		String referenceId = jwsSignRequestDto.getReferenceId();
		if (!keymanagerUtil.isValidApplicationId(applicationId)) {
			applicationId = signApplicationid;
			referenceId = signRefid;
		}

		boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludePayload());
		boolean includeCertificateChain = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertificateChain());
		boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertHash());
		String certificateUrl = SignatureUtil.isDataValid(
				jwsSignRequestDto.getCertificateUrl()) ? jwsSignRequestDto.getCertificateUrl(): null;
		boolean b64JWSHeaderParam = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getB64JWSHeaderParam());
		String signAlgorithm = (jwsSignRequestDto.getSignAlgorithm() == null || jwsSignRequestDto.getSignAlgorithm().isBlank()) ?
				SignatureUtil.getSignAlgorithm(referenceId) : jwsSignRequestDto.getSignAlgorithm();

		SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
				Optional.of(referenceId), timestamp);
		keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
				DateUtils2.parseUTCToDate(timestamp));
		PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
		X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
		String providerName = certificateResponse.getProviderName();
		String uniqueIdentifier = certificateResponse.getUniqueIdentifier();
		Map<String, String> additionalHeaders = jwsSignRequestDto.getAdditionalHeaders();

		JWSHeader jwsHeader = signatureUtil.getJWSHeaderV2(signAlgorithm, b64JWSHeaderParam, includeCertificateChain,
				includeCertHash, certificateUrl, x509Certificate, uniqueIdentifier, includeKeyId, kidPrefix, additionalHeaders);

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
		responseDto.setTimestamp(DateUtils2.getUTCCurrentDateTime());
		if (referenceId.equals(KeyReferenceIdConsts.ED25519_SIGN.name())) {
			LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Found Ed25519 Key for Signature, clearing the Key from memory.");
			privateKey = null;
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
				"JWS Signature Request - Completed.");
		return responseDto;
	}

	@Override
	public JWTSignatureVerifyResponseDto jwtVerifyV2(JWTSignatureVerifyRequestDto jwtVerifyRequestDto) {
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
            reqCertData = keymanagerUtil.getPEMFormatedData(reqCertToVerify);
		}

		List<Certificate> certChain = certificateExistsInHeaderV2(jwtTokens[0]);

		JWTSignatureVerifyResponseDto responseDto = new JWTSignatureVerifyResponseDto();
		responseDto.setSignatureValid(signatureValid);
		responseDto.setMessage(signatureValid ? SignatureConstant.VALIDATION_SUCCESSFUL : SignatureConstant.VALIDATION_FAILED);
		responseDto.setTrustValid(validateTrustV2(jwtVerifyRequestDto, certChain, reqCertData));
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request - Completed.");
		return responseDto;
	}

	@SuppressWarnings("unchecked")
	private List<Certificate> certificateExistsInHeaderV2(String jwtHeader) {
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
			List<Certificate> certChain = new ArrayList<>();
			for (String certData : certList) {
				certChain.add(keymanagerUtil.convertToCertificate(Base64.decodeBase64(certData)));
			}
			return certChain;
		}
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"Certificate not found in JWT Header.");
		return null;
	}

	private String validateTrustV2(JWTSignatureVerifyRequestDto jwtVerifyRequestDto, List<Certificate> headerCertificateChain, String reqCertData) {
		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request - Trust Validation.");
		boolean validateTrust = SignatureUtil.isIncludeAttrsValid(jwtVerifyRequestDto.getValidateTrust());
		if (!validateTrust) {
			return SignatureConstant.TRUST_NOT_VERIFIED;
		}

		List<X509Certificate> x509CertChain = headerCertificateChain.stream()
				.map(cert -> (X509Certificate) cert)
				.toList();

		X509Certificate rootCert = x509CertChain.getLast();

		Set<X509Certificate> intermediateCerts = new HashSet<>();
		intermediateCerts.addAll(x509CertChain.subList(0, x509CertChain.size() - 1));

        String domain = jwtVerifyRequestDto.getDomain();
		if(!SignatureUtil.isDataValid(domain))
			return SignatureConstant.TRUST_NOT_VERIFIED_NO_DOMAIN;

		X509Certificate leafCert = x509CertChain.getFirst();

		X509Certificate trustCertData = leafCert == null ? (X509Certificate) keymanagerUtil.convertToCertificate(reqCertData) : leafCert;
		if (trustCertData == null)
			return SignatureConstant.TRUST_NOT_VERIFIED;

		boolean isTrustValid = partnerCertManagerService.validateCertificatePathWithInterCertTrust(trustCertData, domain, intermediateCerts);
		if (isTrustValid) {
			return SignatureConstant.TRUST_VALID;
		}

		LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
				"JWT Signature Verification Request - Trust Validation - Completed.");
		return SignatureConstant.TRUST_NOT_VALID;
	}
}
