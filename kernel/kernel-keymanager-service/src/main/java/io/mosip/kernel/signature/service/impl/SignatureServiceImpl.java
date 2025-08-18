package io.mosip.kernel.signature.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.crypto.SecretKey;

import io.ipfs.multibase.Multibase;
import io.mosip.kernel.signature.dto.*;
import io.mosip.kernel.signature.service.SignatureServicev2;
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
    private KeymanagerUtil keymanagerUtil;

    @Autowired
    private PDFGenerator pdfGenerator;

    /**
     * Instance for PartnerCertificateManagerService
     */
    @Autowired
    private PartnerCertificateManagerService partnerCertManagerService;

    @Autowired
    private CryptomanagerUtils cryptomanagerUtil;

    @Autowired
    private ECKeyStore ecKeyStore;

    private static Map<String, SignatureProvider> SIGNATURE_PROVIDER = new HashMap<>();

    private AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory;

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
        // Build timestamp once and reuse it (also returned in response)
        final String timestamp = DateUtils.getUTCCurrentDateTimeString();

        SignatureRequestDto signatureRequestDto = new SignatureRequestDto();
        signatureRequestDto.setApplicationId(signApplicationid);
        signatureRequestDto.setReferenceId(signRefid);
        signatureRequestDto.setData(signRequestDto.getData());
        signatureRequestDto.setTimeStamp(timestamp);

        final SignatureResponseDto signatureResponseDTO = sign(signatureRequestDto);
        return new SignatureResponse(signatureResponseDTO.getData(), DateUtils.convertUTCToLocalDateTime(timestamp));
    }

    private SignatureResponseDto sign(SignatureRequestDto signatureRequestDto) {
        SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(
                signatureRequestDto.getApplicationId(), Optional.of(signatureRequestDto.getReferenceId()),
                signatureRequestDto.getTimeStamp());

        final java.util.Date tsDate = DateUtils.parseUTCToDate(signatureRequestDto.getTimeStamp());
        keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(), tsDate);

        String encryptedSignedData = null;
        if (certificateResponse.getCertificateEntry() != null) {
            encryptedSignedData = cryptoCore.sign(signatureRequestDto.getData().getBytes(StandardCharsets.UTF_8),
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
        }
        throw new SignatureFailureException(SignatureErrorCode.NOT_VALID.getErrorCode(),
                SignatureErrorCode.NOT_VALID.getErrorMessage(), null);
    }

    @Override
    public SignatureResponseDto signPDF(PDFSignatureRequestDto request) {
        final SignatureCertificate signatureCertificate = keymanagerService.getSignatureCertificate(
                request.getApplicationId(), Optional.of(request.getReferenceId()), request.getTimeStamp());

        LOGGER.debug(KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID, KeymanagerConstant.SESSIONID,
                "Signature fetched from hsm " + signatureCertificate);

        // Precompute rectangle once
        final Rectangle rectangle = new Rectangle(
                request.getLowerLeftX(), request.getLowerLeftY(),
                request.getUpperRightX(), request.getUpperRightY());

        OutputStream outputStream;
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

        if (!cryptomanagerUtil.hasKeyAccess(jwtSignRequestDto.getApplicationId())) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                    "Signing Data is not allowed for the authenticated user for the provided application id. " +
                            " App Id: " + jwtSignRequestDto.getApplicationId());
            throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
                    SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
        }

        final String reqDataToSign = jwtSignRequestDto.getDataToSign();
        if (!SignatureUtil.isDataValid(reqDataToSign)) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                    "Provided Data to sign is invalid.");
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                    SignatureErrorCode.INVALID_INPUT.getErrorMessage());
        }

        final String decodedDataToSign = new String(CryptoUtil.decodeURLSafeBase64(reqDataToSign), StandardCharsets.UTF_8);

        if (confValidateJson && !SignatureUtil.isJsonValid(decodedDataToSign)) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                    "Provided Data to sign is invalid JSON.");
            throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
                    SignatureErrorCode.INVALID_JSON.getErrorMessage());
        }

        final String timestamp = DateUtils.getUTCCurrentDateTimeString();
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
                DateUtils.parseUTCToDate(timestamp));

        final String signedData = sign(decodedDataToSign, certificateResponse, includePayload, includeCertificate,
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

        // Optional detached payload (must already be base64url-encoded if provided)
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

    private String validateTrust(JWTSignatureVerifyRequestDto jwtVerifyRequestDto, Certificate headerCertificate, String reqCertData) {
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                "JWT Signature Verification Request - Trust Validation.");
        if (!SignatureUtil.isIncludeAttrsValid(jwtVerifyRequestDto.getValidateTrust())) {
            return SignatureConstant.TRUST_NOT_VERIFIED;
        }

        final String domain = jwtVerifyRequestDto.getDomain();
        if(!SignatureUtil.isDataValid(domain))
            return SignatureConstant.TRUST_NOT_VERIFIED_NO_DOMAIN;

        // Choose cert data source (prefer header cert if present)
        String trustCertData = null;
        String fp = null; // fingerprint for cache key

        if (headerCertificate instanceof X509Certificate x509) {
            // Fast fingerprint for cache (x5t#S256 of DER)
            fp = computeX5tS256(x509);
            // Defer PEM conversion unless we miss the cache
            trustCertData = null; // will lazily fill below if needed
        } else if (SignatureUtil.isDataValid(reqCertData)) {
            // Use a cheap fingerprint of the provided PEM/DER string
            fp = b64NoPad(sha256(reqCertData.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            trustCertData = reqCertData;
        }

        if (fp == null) {
            // No certificate material to verify trust against
            return SignatureConstant.TRUST_NOT_VERIFIED;
        }
        // --- Cache lookup (domain + fingerprint) ---
        final String tKey = cacheKey("TRUST", domain, fp);
        final long now = System.currentTimeMillis();
        final BoolWithTs cached = trustCache.get(tKey);
        if (cached != null && (now - cached.ts) < TRUST_TTL_MS) {
            return cached.v ? SignatureConstant.TRUST_VALID : SignatureConstant.TRUST_NOT_VALID;
        }

        // Prepare certificate data if we didn’t have it yet (only on cache miss)
        if (trustCertData == null && headerCertificate != null) {
            trustCertData = keymanagerUtil.getPEMFormatedData(headerCertificate);
        }
        if (!SignatureUtil.isDataValid(trustCertData)) {
            return SignatureConstant.TRUST_NOT_VERIFIED;
        }

        // Call partner service
        CertificateTrustRequestDto trustRequestDto = new CertificateTrustRequestDto();
        trustRequestDto.setCertificateData(trustCertData);
        trustRequestDto.setPartnerDomain(domain);

        CertificateTrustResponeDto resp = partnerCertManagerService.verifyCertificateTrust(trustRequestDto);

        // Memoize result
        trustCache.put(tKey, new BoolWithTs(resp.getStatus(), now));

        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                "JWT Signature Verification Request - Trust Validation - Completed.");

        return resp.getStatus() ? SignatureConstant.TRUST_VALID : SignatureConstant.TRUST_NOT_VALID;
    }

    @Override
    public JWTSignatureResponseDto jwsSign(JWSSignatureRequestDto jwsSignRequestDto) {
        // TODO Code is duplicated from jwtSign method. Duplicate code will be removed later when VC verification is implement.
        // Code duplicated because now does not want to make any change to existing code which is well tested.
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
                "JWS Signature Request.");

        if (!cryptomanagerUtil.hasKeyAccess(jwsSignRequestDto.getApplicationId())) {
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

        // decode once (UTF-8) + optional JSON validation
        final String decodedDataToSign =
                new String(CryptoUtil.decodeURLSafeBase64(reqDataToSign), StandardCharsets.UTF_8);
        if (confValidateJson && !SignatureUtil.isJsonValid(decodedDataToSign)) {
            throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
                    SignatureErrorCode.INVALID_JSON.getErrorMessage());
        }

        final String timestamp = DateUtils.getUTCCurrentDateTimeString();
        String applicationId = jwsSignRequestDto.getApplicationId();
        String referenceId = jwsSignRequestDto.getReferenceId();
        if (!keymanagerUtil.isValidApplicationId(applicationId)) {
            applicationId = signApplicationid;
            referenceId = signRefid;
        }

        // flags
        final boolean includePayload = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludePayload());
        final boolean includeCertificate = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertificate());
        final boolean includeCertHash = SignatureUtil.isIncludeAttrsValid(jwsSignRequestDto.getIncludeCertHash());
        final String certificateUrl = SignatureUtil.isDataValid(
                jwsSignRequestDto.getCertificateUrl()) ? jwsSignRequestDto.getCertificateUrl(): null;

        // signing material
        final SignatureCertificate certResp =
                keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp);
        keymanagerUtil.isCertificateValid(certResp.getCertificateEntry(),
                DateUtils.parseUTCToDate(timestamp));

        // delegate to fast sign(...)
        final String jwt = sign(decodedDataToSign, certResp, includePayload,
                includeCertificate, includeCertHash, certificateUrl, referenceId);

        JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
        responseDto.setJwtSignedData(jwt);
        responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
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
        String timestamp = DateUtils.getUTCCurrentDateTimeString();
        if (!keymanagerUtil.isValidApplicationId(applicationId)) {
            applicationId = signApplicationid;
            referenceId = signRefid;
        }
        String signAlgorithm = SignatureUtil.isDataValid(signatureReq.getSignAlgorithm()) ?
                signatureReq.getSignAlgorithm(): SignatureConstant.ED25519_ALGORITHM;

        SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,
                Optional.of(referenceId), timestamp);
        keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(),
                DateUtils.parseUTCToDate(timestamp));
        PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();
        certificateResponse.getCertificateEntry().getChain();
        String providerName = certificateResponse.getProviderName();
        SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get(signAlgorithm);
        if (Objects.isNull(signatureProvider)) {
            signatureProvider = SIGNATURE_PROVIDER.get(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST);
        }
        String signature = signatureProvider.sign(privateKey, dataToSign, providerName);
        byte[] data = java.util.Base64.getUrlDecoder().decode(signature);
        SignResponseDto signedData = new SignResponseDto();
        signedData.setTimestamp(DateUtils.getUTCCurrentDateTime());
        switch (signatureReq.getResponseEncodingFormat()) {
            case "base64url":
                signedData.setSignature(
                        Multibase.encode(Multibase.Base.Base64Url, data));
                break;
            case "base58btc":
                signedData.setSignature(
                        Multibase.encode(Multibase.Base.Base58BTC, data));
                break;
            default:
                throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_FORMAT_ERROR.getErrorCode(),
                        KeymanagerErrorConstant.INVALID_FORMAT_ERROR.getErrorMessage());
        }
        return signedData;
    }

    @Override
    public SignResponseDtoV2 rawSign(SignRequestDtoV2 signatureReq) {
        return null;
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
}
