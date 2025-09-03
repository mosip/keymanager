package io.mosip.kernel.signature.service.impl;

import com.authlete.cbor.*;
import com.authlete.cose.*;
import com.authlete.cose.constants.COSEAlgorithms;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import com.upokecenter.cbor.CBORObject;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keygenerator.bouncycastle.util.KeyGeneratorUtils;
import io.mosip.kernel.keymanagerservice.constant.KeyReferenceIdConsts;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.dto.*;
import io.mosip.kernel.signature.exception.CertificateNotValidException;
import io.mosip.kernel.signature.exception.RequestException;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.service.CoseSignatureService;
import io.mosip.kernel.signature.service.SignatureProvider;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.kernel.signature.util.SignatureUtil;
import io.mosip.kernel.signature.builder.CoseHeaderBuilder;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class CoseSignatureServiceImpl implements CoseSignatureService {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(CoseSignatureServiceImpl.class);

    @Autowired
    KeymanagerUtil keymanagerUtil;

    @Autowired
    CryptomanagerUtils cryptomanagerUtil;

    @Autowired
    KeymanagerService keymanagerService;

    @Autowired
    SignatureService signatureService;

    /** The sign applicationid. */
    @Value("${mosip.sign.applicationid:KERNEL}")
    private String signApplicationid;

    /** The sign refid. */
    @Value("${mosip.sign.refid:SIGN}")
    private String signRefid;

    @Value("${mosip.kernel.keymanager.jwtsign.include.keyid:true}")
    private boolean includeKeyId;

    @Value("${mosip.kernel.keymanager.signature.kid.prepend:}")
    private String kidPrepend;

    private static final ObjectMapper mapper = JsonMapper.builder().addModule(new AfterburnerModule()).build();
    private static final Map<String, SignatureProvider> SIGNATURE_PROVIDER = new HashMap<>();

    static {
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST, new PS256SIgnatureProviderImpl());
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_RS256_SIGN_ALGO_CONST, new RS256SignatureProviderImpl());
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_ES256_SIGN_ALGO_CONST, new EC256SignatureProviderImpl());
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_ES256K_SIGN_ALGO_CONST, new EC256SignatureProviderImpl());
        SIGNATURE_PROVIDER.put(SignatureConstant.JWS_EDDSA_SIGN_ALGO_CONST, new Ed25519SignatureProviderImpl());
    }

    private static final Map<String, String> COSE_SIGNATURE_ALGO_IDENT = new HashMap<>();
    static {
        COSE_SIGNATURE_ALGO_IDENT.put(SignatureConstant.BLANK, AlgorithmIdentifiers.RSA_USING_SHA256);
        COSE_SIGNATURE_ALGO_IDENT.put(SignatureConstant.REF_ID_SIGN_CONST, AlgorithmIdentifiers.RSA_USING_SHA256);
        COSE_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name(), AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256);
        COSE_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name(), AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        COSE_SIGNATURE_ALGO_IDENT.put(KeyReferenceIdConsts.ED25519_SIGN.name(), AlgorithmIdentifiers.EDDSA);
    }

    private static final Map<String, String> COSE_ALGORITHM_INSTANCE = new HashMap<>();
    static {
        COSE_ALGORITHM_INSTANCE.put(AlgorithmIdentifiers.RSA_USING_SHA256, SignatureConstant.RS256_ALGORITHM);
        COSE_ALGORITHM_INSTANCE.put(AlgorithmIdentifiers.RSA_PSS_USING_SHA256, SignatureConstant.RSA_PS256_SIGN_ALGORITHM_INSTANCE);
        COSE_ALGORITHM_INSTANCE.put(AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256, SignatureConstant.EC256_ALGORITHM);
        COSE_ALGORITHM_INSTANCE.put(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256, SignatureConstant.EC256_ALGORITHM);
        COSE_ALGORITHM_INSTANCE.put(AlgorithmIdentifiers.EDDSA, SignatureConstant.ED25519_ALGORITHM);
    }

    @Override
    public CoseSignResponseDto coseSign(CoseSignRequestDto coseSignRequestDto) {
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                "COSE Signature Request.");

        if (!cryptomanagerUtil.hasKeyAccess(coseSignRequestDto.getApplicationId())) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                    "Signing Data is not allowed for the authenticated user for the provided application id." + " App Id: " + coseSignRequestDto.getApplicationId());
            throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
                    SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
        }

        String base64Payload = coseSignRequestDto.getPayload();
        if (!SignatureUtil.isDataValid(base64Payload)) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                    "Provided Data to sign is invalid.");
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                    SignatureErrorCode.INVALID_INPUT.getErrorMessage());
        }

        String payload = new String(CryptoUtil.decodeURLSafeBase64(base64Payload));

        String timestamp = DateUtils.getUTCCurrentDateTimeString();
        String applicationId = coseSignRequestDto.getApplicationId();
        String referenceId = coseSignRequestDto.getReferenceId();
        if (!keymanagerUtil.isValidApplicationId(applicationId)) {
            applicationId = signApplicationid;
            referenceId = signRefid;
        }

        SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId,	Optional.of(referenceId), timestamp);
        keymanagerUtil.isCertificateValid(certificateResponse.getCertificateEntry(), DateUtils.parseUTCToDate(timestamp));

        String signedData = signCose(payload, certificateResponse, referenceId, coseSignRequestDto);

        CoseSignResponseDto responseDto = new CoseSignResponseDto();
        responseDto.setSignedData(signedData);
        responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                "COSE Signature Request - Completed.");
        return responseDto;
    }

    private String signCose(String cosePayload,	SignatureCertificate certificateResponse, String referenceId, CoseSignRequestDto requestDto) {
        try {

            String algorithm = requestDto.getAlgorithm() == null || requestDto.getAlgorithm().isEmpty() ?
                    COSE_SIGNATURE_ALGO_IDENT.get(referenceId) : requestDto.getAlgorithm();
            COSEProtectedHeaderBuilder protectedHeaderBuilder = buildCoseProtectedHeader(certificateResponse, algorithm, requestDto);
            COSEUnprotectedHeaderBuilder unprotectedHeaderBuilder = buildCoseUnprotectedHeader(certificateResponse, requestDto);
            String keyId = getKeyId(kidPrepend, certificateResponse, requestDto, includeKeyId);
            if (keyId != null && Boolean.TRUE.equals(requestDto.getProtectedHeader().get("kid"))) {
                protectedHeaderBuilder.kid(keyId);
            } else if (keyId != null) {
                unprotectedHeaderBuilder.kid(keyId);
            }

            PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();

            COSEProtectedHeader protectedHeader = protectedHeaderBuilder.build();
            COSEUnprotectedHeader unprotectedHeader = unprotectedHeaderBuilder.build();

            SigStructure sigStructure = new SigStructureBuilder()
                    .signature1()
                    .bodyAttributes(protectedHeader)
                    .payload(cosePayload)
                    .build();

            SignatureProvider signatureProvider = SIGNATURE_PROVIDER.get(algorithm);
            if (Objects.isNull(signatureProvider)) {
                signatureProvider = SIGNATURE_PROVIDER.get(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST);
            }

            String b64Signature = signatureProvider.sign(privateKey, sigStructure.encode(), certificateResponse.getProviderName());
            byte[] signature = CryptoUtil.decodeURLSafeBase64(b64Signature);

            COSESign1 coseSign1 = new COSESign1Builder()
                    .protectedHeader(protectedHeader)
                    .unprotectedHeader(unprotectedHeader)
                    .payload(cosePayload)
                    .signature(signature)
                    .build();

            byte[] coseBytes = coseSign1.encode();
            CBORDecoder decoder = new CBORDecoder(coseBytes);
            CBORItem coseItem = decoder.next();
            CBORTaggedItem sign1Tagged = new CBORTaggedItem(18, coseItem);
            byte[] taggedCoseSign1 = sign1Tagged.encode();

            return bytesToHex(taggedCoseSign1);
        } catch (Exception e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                    "Error occurred while signing COSE data.", e);
            throw new SignatureFailureException(SignatureErrorCode.COSE_SIGN_ERROR.getErrorCode(),
                    SignatureErrorCode.COSE_SIGN_ERROR.getErrorMessage(), e);
        }
    }

    @Override
    public CoseSignVerifyResponseDto coseVerify(CoseSignVerifyRequestDto requestDto) {
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                "COSE Signature Verification Request.");

        try {
            String coseHexdata = requestDto.getCoseSignedData();
            if (!SignatureUtil.isDataValid(coseHexdata)) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Provided COSE data is invalid.");
                throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                        SignatureErrorCode.INVALID_INPUT.getErrorMessage());
            }

            String reqCertData = SignatureUtil.isDataValid(requestDto.getCertificateData()) ? requestDto.getCertificateData() : null;
            String applicationId = requestDto.getApplicationId();
            String referenceId = requestDto.getReferenceId();
            if (!keymanagerUtil.isValidApplicationId(applicationId)) {
                applicationId = signApplicationid;
                referenceId = signRefid;
            }

            byte[] coseData = hexStringToByteArray(coseHexdata);
            CBORDecoder cborDecoder = new CBORDecoder(coseData);
            CBORTaggedItem cborTaggedItem = (CBORTaggedItem) cborDecoder.next();
            COSESign1 coseSign1 = (COSESign1) cborTaggedItem.getTagContent();

            COSEProtectedHeader protectedHeader = coseSign1.getProtectedHeader();
            COSEUnprotectedHeader unprotectedHeader = coseSign1.getUnprotectedHeader();

            boolean signatureValid;
            Certificate certToVerify = certificateExistsInProtectedHeader(protectedHeader) != null ?
                    certificateExistsInProtectedHeader(protectedHeader) : certificateExistsInUnprotectedHeader(unprotectedHeader);
            if (Objects.nonNull(certToVerify)){
                signatureValid =verifyCoseSignature(coseSign1,certToVerify);
            } else {
                Certificate reqCertToVerify = getCertificateToVerify(reqCertData, applicationId, referenceId);
                signatureValid = verifyCoseSignature(coseSign1,reqCertToVerify);
            }


            LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "COSE Signature Verification Status: " + signatureValid);
            List<X509Certificate> x5Chain = protectedHeader.getX5Chain() != null ? protectedHeader.getX5Chain() : unprotectedHeader.getX5Chain();

            JWTSignatureVerifyRequestDto jwtVerifyRequestDto = new JWTSignatureVerifyRequestDto();
            jwtVerifyRequestDto.setValidateTrust(requestDto.getValidateTrust());
            jwtVerifyRequestDto.setDomain(requestDto.getDomain());
            String isTrustValid;

            if (x5Chain == null) {
                LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Certificate not found in COSE Header.");
                isTrustValid = SignatureConstant.TRUST_VALID;
            }else if (x5Chain.size() > 1) {
                List<Certificate> certificateList = new ArrayList<>(x5Chain);
                isTrustValid = signatureService.validateTrustV2(jwtVerifyRequestDto, certificateList , reqCertData);
            } else {
                Certificate certificate = x5Chain.getFirst();
                isTrustValid = signatureService.validateTrust(jwtVerifyRequestDto, certificate, reqCertData);
            }

            CoseSignVerifyResponseDto responseDto = new CoseSignVerifyResponseDto();
            responseDto.setSignatureValid(signatureValid);
            responseDto.setMessage(signatureValid ? SignatureConstant.VALIDATION_SUCCESSFUL : SignatureConstant.VALIDATION_FAILED);
            responseDto.setTrustValid(isTrustValid);
            return responseDto;
        } catch (Exception e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Error occurred while verifying COSE data.", e);
            throw new SignatureFailureException(SignatureErrorCode.COSE_VERIFY_ERROR.getErrorCode(),
                    SignatureErrorCode.COSE_VERIFY_ERROR.getErrorMessage(), e);
        }
    }

    private Certificate certificateExistsInProtectedHeader(COSEProtectedHeader protectedHeader) {
        if (protectedHeader.getX5Chain() != null && !protectedHeader.getX5Chain().isEmpty()) {
            LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Certificate found in COSE Protected Header.");
            return protectedHeader.getX5Chain().getFirst();
        } else {
            LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Certificate not found in COSE Protected Header.");
            return null;
        }
    }

    private Certificate certificateExistsInUnprotectedHeader(COSEUnprotectedHeader unprotectedHeader) {
        if (unprotectedHeader.getX5Chain() != null && !unprotectedHeader.getX5Chain().isEmpty()) {
            LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Certificate found in COSE Unprotected Header.");
            return unprotectedHeader.getX5Chain().getFirst();
        } else {
            LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Certificate not found in COSE Unprotected Header.");
            return null;
        }
    }

    private Certificate getCertificateToVerify(String reqCertData, String applicationId, String referenceId) {
        if (reqCertData != null)
            return keymanagerUtil.convertToCertificate(reqCertData);
        KeyPairGenerateResponseDto certificateResponse = keymanagerService.getCertificate(applicationId,
                Optional.of(referenceId));
        return keymanagerUtil.convertToCertificate(certificateResponse.getCertificate());
    }

    private boolean verifyCoseSignature(COSESign1 coseSign1, Certificate reqCertToVerify) {

        try {
            X509Certificate x509CertToVerify = (X509Certificate) reqCertToVerify;
            boolean validCert = SignatureUtil.isCertificateDatesValid(x509CertToVerify);
            if (!validCert) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
                        "Error certificate dates are not valid.");
                throw new CertificateNotValidException(SignatureErrorCode.CERT_NOT_VALID.getErrorCode(),
                        SignatureErrorCode.CERT_NOT_VALID.getErrorMessage());
            }

            String keyAlgorithm = x509CertToVerify.getPublicKey().getAlgorithm();
            PublicKey publicKey;
            if (keyAlgorithm.equals(KeymanagerConstant.EDDSA_KEY_TYPE)) {
                LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Found Ed25519 Certificate for Signature verification.");
                publicKey = KeyGeneratorUtils.createPublicKey(KeymanagerConstant.ED25519_KEY_TYPE,
                        x509CertToVerify.getPublicKey().getEncoded());
            } else if (keyAlgorithm.equals(KeymanagerConstant.EC_KEY_TYPE)) {
                LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Found EC Certificate for Signature verification.");
                publicKey = KeyGeneratorUtils.createPublicKey(keyAlgorithm, x509CertToVerify.getPublicKey().getEncoded());
            } else {
                publicKey = x509CertToVerify.getPublicKey();
            }

            SigStructure sigStructure = new SigStructureBuilder()
                    .signature1()
                    .bodyAttributes(coseSign1.getProtectedHeader())
                    .payload((CBORByteArray) coseSign1.getPayload())
                    .build();

            String algorithm = getCoseAlgorithmString((int) coseSign1.getProtectedHeader().getAlg());

            if (keyAlgorithm.equals(KeymanagerConstant.EC_KEY_TYPE)) {
                Signature verifier = Signature.getInstance(COSE_ALGORITHM_INSTANCE.get(algorithm), SignatureConstant.BC_PROVIDER);
                verifier.initVerify(publicKey);
                verifier.update(sigStructure.encode());
                return verifier.verify(convertRawECSignatureToDER(coseSign1.getSignature().getValue()));
            } else {
                Signature verifier = Signature.getInstance(COSE_ALGORITHM_INSTANCE.get(algorithm));
                verifier.initVerify(publicKey);
                verifier.update(sigStructure.encode());
                return verifier.verify(coseSign1.getSignature().getValue());
            }
        } catch (Exception e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Error occurred while verifying COSE data.", e);
            throw new SignatureFailureException(SignatureErrorCode.COSE_VERIFY_ERROR.getErrorCode(),
                    SignatureErrorCode.COSE_VERIFY_ERROR.getErrorMessage(), e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private byte[] hexStringToByteArray(String hex) {
        int length = hex.length();
        if (length % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string length.");
        }
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            int firstDigit = Character.digit(hex.charAt(i), 16);
            int secondDigit = Character.digit(hex.charAt(i + 1), 16);
            if (firstDigit == -1 || secondDigit == -1) {
                throw new IllegalArgumentException("Invalid hex character at position " + i);
            }
            data[i / 2] = (byte) ((firstDigit << 4) + secondDigit);
        }
        return data;
    }

    public COSEProtectedHeaderBuilder buildCoseProtectedHeader(SignatureCertificate certificateResponse, String algorithm, CoseSignRequestDto requestDto) {
        Integer coseAlg = getCoseAlgorithm(algorithm);
        return new CoseHeaderBuilder(certificateResponse, requestDto, coseAlg, keymanagerUtil, LOGGER).buildProtected();
    }

    public COSEUnprotectedHeaderBuilder buildCoseUnprotectedHeader(SignatureCertificate certificateResponse, CoseSignRequestDto requestDto) {
        return new CoseHeaderBuilder(certificateResponse, requestDto, null, keymanagerUtil, LOGGER).buildUnprotected();
    }

    public String getKeyId(String kidPrepend, SignatureCertificate certificateResponse, CoseSignRequestDto requestDto, boolean includeKeyId) {

        if ((requestDto.getProtectedHeader() != null && requestDto.getProtectedHeader().containsKey("kid")) ||
                (requestDto.getUnprotectedHeader() != null && requestDto.getUnprotectedHeader().containsKey("kid"))) {
            String kidPrefix = kidPrepend;
            if (kidPrepend.equalsIgnoreCase(SignatureConstant.KEY_ID_PREFIX)) {
                kidPrefix = SignatureUtil.getIssuerFromPayload(requestDto.getPayload()).concat(SignatureConstant.KEY_ID_SEPARATOR);
            }
            String keyId = SignatureUtil.convertHexToBase64(certificateResponse.getUniqueIdentifier());
            if (includeKeyId && Objects.nonNull(keyId)) {
                return kidPrefix.concat(keyId);
            }
        }
        return null;
    }

    public int getCoseAlgorithm(String signAlgorithm) {
        return switch (signAlgorithm) {
            case AlgorithmIdentifiers.RSA_USING_SHA256 -> COSEAlgorithms.RS256;
            case AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256 -> COSEAlgorithms.ES256K;
            case AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256 -> COSEAlgorithms.ES256;
            case AlgorithmIdentifiers.EDDSA -> COSEAlgorithms.EdDSA;
            default -> COSEAlgorithms.PS256;
        };
    }

    public String getCoseAlgorithmString(int coseAlgorithm) {
        return switch (coseAlgorithm) {
            case COSEAlgorithms.PS256 -> AlgorithmIdentifiers.RSA_PSS_USING_SHA256;
            case COSEAlgorithms.ES256K -> AlgorithmIdentifiers.ECDSA_USING_SECP256K1_CURVE_AND_SHA256;
            case COSEAlgorithms.ES256 -> AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;
            case COSEAlgorithms.EdDSA -> AlgorithmIdentifiers.EDDSA;
            default -> AlgorithmIdentifiers.RSA_USING_SHA256;
        };
    }

    public byte[] convertToCborClaims(String payload) {
        try {
            JsonNode jsonNode = mapper.readTree(payload);
            Map<Object, Object> cborClaimsMap = new HashMap<>();

            Map<String, Integer> registeredClaimKeys = Map.of(
                    "iss", 1,
                    "sub", 2,
                    "aud", 3,
                    "exp", 4,
                    "nbf", 5,
                    "iat", 6,
                    "cti", 7
            );

            Iterator<Map.Entry<String, JsonNode>> fields = jsonNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String jsonKey = field.getKey();
                JsonNode jsonValue = field.getValue();

                Object cborKey;
                if (registeredClaimKeys.containsKey(jsonKey)) {
                    cborKey = registeredClaimKeys.get(jsonKey);
                } else {
                    try {
                        cborKey = Integer.parseInt(jsonKey);
                    } catch (NumberFormatException e) {
                        cborKey = jsonKey;
                    }
                }

                Object cborValue;
                if (jsonValue.isNumber()) {
                    cborValue = jsonValue.numberValue();
                } else if (jsonValue.isBoolean()) {
                    cborValue = jsonValue.booleanValue();
                } else if (jsonValue.isContainerNode()) {
                    cborValue = mapper.convertValue(jsonValue, Object.class);
                } else {
                    cborValue = jsonValue.asText();
                }

                cborClaimsMap.put(cborKey, cborValue);
            }

            CBORObject cborPayload = CBORObject.FromObject(cborClaimsMap);
            return cborPayload.EncodeToBytes();
        } catch (JsonProcessingException e) {
            LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                    "Payload is not a valid JSON. Treating as plain string.");
            CBORObject cborPayload = CBORObject.FromObject(payload);
            return cborPayload.EncodeToBytes();
        }
    }

    private byte[] convertRawECSignatureToDER(byte[] rawSignature) {
        try {
            int len = rawSignature.length / 2;
            byte[] rBytes = Arrays.copyOfRange(rawSignature, 0, len);
            byte[] sBytes = Arrays.copyOfRange(rawSignature, len, rawSignature.length);

            BigInteger r = new BigInteger(1, rBytes);
            BigInteger s = new BigInteger(1, sBytes);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DERSequenceGenerator seq = new DERSequenceGenerator(baos);
            seq.addObject(new ASN1Integer(r));
            seq.addObject(new ASN1Integer(s));
            seq.close();

            return baos.toByteArray();

        } catch (Exception e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Error converting raw EC signature to DER format.", e);
            throw new SignatureFailureException(SignatureErrorCode.COSE_VERIFY_ERROR.getErrorCode(),
                    "Error converting raw EC signature to DER format.", e);
        }
    }
}
