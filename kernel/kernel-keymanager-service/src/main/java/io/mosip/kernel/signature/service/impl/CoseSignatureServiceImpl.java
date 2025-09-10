package io.mosip.kernel.signature.service.impl;

import com.authlete.cbor.*;
import com.authlete.cose.*;
import com.authlete.cose.constants.COSEAlgorithms;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keygenerator.bouncycastle.util.KeyGeneratorUtils;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.signature.constant.*;
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
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
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

    @Autowired
    SignatureUtil signatureUtil;

    @Autowired
    CoseHeaderBuilder coseHeaderBuilder;

    @Autowired
    ECKeyStore ecKeyStore;

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

    @Override
    public CoseSignResponseDto coseSign1(CoseSignRequestDto coseSignRequestDto) {
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
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
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
        String signedData = signCose1(payload.getBytes(StandardCharsets.UTF_8), certificateResponse, referenceId, coseSignRequestDto, false);

        CoseSignResponseDto responseDto = new CoseSignResponseDto();
        responseDto.setSignedData(signedData);
        responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                "COSE Signature Request - Completed.");
        return responseDto;
    }

    private String signCose1(byte[] cosePayload, SignatureCertificate certificateResponse, String referenceId, CoseSignRequestDto requestDto, boolean isCwt) {
        try {
            String algorithm = (requestDto.getAlgorithm() == null || requestDto.getAlgorithm().isEmpty()) ?
                    SignatureAlgorithmIdentifyEnum.getAlgorithmIdentifier(referenceId) : requestDto.getAlgorithm();
            COSEProtectedHeaderBuilder protectedHeaderBuilder = coseHeaderBuilder.buildProtectedHeader(certificateResponse, requestDto, getCoseAlgorithm(algorithm), keymanagerUtil);
            COSEUnprotectedHeaderBuilder unprotectedHeaderBuilder = coseHeaderBuilder.buildUnprotectedHeader(certificateResponse, requestDto, keymanagerUtil);
            String keyId = getKeyId(kidPrepend, certificateResponse, requestDto, includeKeyId);
            setKidHeader(keyId, requestDto, protectedHeaderBuilder, unprotectedHeaderBuilder);

            PrivateKey privateKey = certificateResponse.getCertificateEntry().getPrivateKey();

            COSEProtectedHeader protectedHeader = protectedHeaderBuilder.build();
            COSEUnprotectedHeader unprotectedHeader = unprotectedHeaderBuilder.build();

            SigStructure sigStructure = new SigStructureBuilder()
                    .signature1()
                    .bodyAttributes(protectedHeader)
                    .payload(cosePayload)
                    .build();

            SignatureProvider signatureProvider = SignatureProviderEnum.getSignatureProvider(algorithm);
            if (Objects.isNull(signatureProvider)) {
                signatureProvider = SignatureProviderEnum.getSignatureProvider(SignatureConstant.JWS_PS256_SIGN_ALGO_CONST);
            }

            String b64Signature = signatureProvider.sign(privateKey, sigStructure.encode(), certificateResponse.getProviderName());
            byte[] signature = CryptoUtil.decodeURLSafeBase64(b64Signature);

            COSESign1 coseSign1 = new COSESign1Builder()
                    .protectedHeader(protectedHeader)
                    .unprotectedHeader(unprotectedHeader)
                    .payload(cosePayload)
                    .signature(signature)
                    .build();

            return bytesToHex(encodeTaggedCoseSign1(coseSign1, isCwt));
        } catch (IOException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                    "Error occurred while signing COSE data.", e);
            throw new SignatureFailureException(SignatureErrorCode.COSE_SIGN_ERROR.getErrorCode(),
                    SignatureErrorCode.COSE_SIGN_ERROR.getErrorMessage(), e);
        }
    }

    private byte[] encodeTaggedCoseSign1(COSESign1 coseSign1, boolean isCwt) throws IOException {
        byte[] coseBytes = coseSign1.encode();
        CBORDecoder decoder = new CBORDecoder(coseBytes);
        CBORItem coseItem = decoder.next();
        CBORTaggedItem sign1Tagged = new CBORTaggedItem(18, coseItem);

        if (isCwt) {
            CBORTaggedItem cwtTagged = new CBORTaggedItem(61, sign1Tagged);
            return cwtTagged.encode();
        } else {
            return sign1Tagged.encode();
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
                throw new RequestException(SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorCode(),
                        SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorMessage());
            }

            String reqCertData = SignatureUtil.isDataValid(requestDto.getCertificateData()) ? requestDto.getCertificateData() : null;
            String applicationId = requestDto.getApplicationId();
            String referenceId = requestDto.getReferenceId() == null ? SignatureConstant.BLANK : requestDto.getReferenceId();
            if (!keymanagerUtil.isValidApplicationId(applicationId)) {
                applicationId = signApplicationid;
                referenceId = signRefid;
            }

            byte[] coseData = hexStringToByteArray(coseHexdata);
            CBORDecoder cborDecoder = new CBORDecoder(coseData);
            CBORTaggedItem cborTaggedItem = (CBORTaggedItem) cborDecoder.next();
            if ((int)cborTaggedItem.getTagNumber() != 18) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Provided CWT data does not have COSE Sign1 Array tag." + " CWT Tag Number: " + cborTaggedItem.getTagNumber());
                throw new RequestException(SignatureErrorCode.INVALID_COSE_SIGN1_INPUT.getErrorCode(),
                        SignatureErrorCode.INVALID_COSE_SIGN1_INPUT.getErrorMessage());
            }

            COSESign1 coseSign1 = (COSESign1) cborTaggedItem.getTagContent();
            boolean signatureValid = verifyCoseSignature(coseSign1, reqCertData, applicationId, referenceId);
            LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "COSE Signature Verification Status: " + signatureValid);

            CoseSignVerifyResponseDto responseDto = new CoseSignVerifyResponseDto();
            responseDto.setSignatureValid(signatureValid);
            responseDto.setMessage(signatureValid ? SignatureConstant.VALIDATION_SUCCESSFUL : SignatureConstant.VALIDATION_FAILED);
            responseDto.setTrustValid(validateTrustForCose(applicationId, referenceId, coseSign1, reqCertData, requestDto));
            return responseDto;
        } catch (IOException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Error occurred while verifying COSE data.", e);
            throw new SignatureFailureException(SignatureErrorCode.COSE_VERIFY_ERROR.getErrorCode(),
                    SignatureErrorCode.COSE_VERIFY_ERROR.getErrorMessage(), e);
        }
    }

    private String validateTrustForCose(String appId, String refId, COSESign1 coseSign1, String reqCertData, CoseSignVerifyRequestDto requestDto) {
        JWTSignatureVerifyRequestDto jwtVerifyRequestDto = new JWTSignatureVerifyRequestDto();
        jwtVerifyRequestDto.setValidateTrust(requestDto.getValidateTrust());
        jwtVerifyRequestDto.setDomain(requestDto.getDomain());

        List<X509Certificate> x5Chain = signatureUtil.getX5ChainfromCoseSign1(coseSign1);
        if (x5Chain == null && reqCertData == null) {
            LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Certificate not found in COSE Header.");
            KeyPairGenerateResponseDto certificateResponse = keymanagerService.getCertificate(appId, Optional.of(refId));
            Certificate reqCertToVerify = keymanagerUtil.convertToCertificate(certificateResponse.getCertificate());
            return signatureService.validateTrust(jwtVerifyRequestDto, reqCertToVerify, certificateResponse.getCertificate());
        } else if (x5Chain == null) {
            LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Certificate not found in COSE Header. Using certificate provided Certificate Data.");
            return signatureService.validateTrust(jwtVerifyRequestDto, keymanagerUtil.convertToCertificate(reqCertData), reqCertData);
        } else if (x5Chain.size() > 1) {
            List<Certificate> certificateList = new ArrayList<>(x5Chain);
            return signatureService.validateTrustV2(jwtVerifyRequestDto, certificateList, reqCertData);
        } else {
            Certificate certificate = x5Chain.getFirst();
            return signatureService.validateTrust(jwtVerifyRequestDto, certificate, reqCertData);
        }
    }

    private boolean verifyCoseSignature(COSESign1 coseSign1, String reqCertData, String applicationId, String referenceId) {
        COSEProtectedHeader protectedHeader = coseSign1.getProtectedHeader();
        COSEUnprotectedHeader unprotectedHeader = coseSign1.getUnprotectedHeader();

        Certificate certToVerify = certificateExistsInProtectedHeader(protectedHeader);
        if (certToVerify == null) {
            certToVerify = certificateExistsInUnprotectedHeader(unprotectedHeader);
        }
        if (certToVerify == null) {
            certToVerify = getCertificateToVerify(reqCertData, applicationId, referenceId);
        }

        X509Certificate x509CertToVerify = (X509Certificate) certToVerify;
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
        } else {
            publicKey = x509CertToVerify.getPublicKey();
        }

        SigStructure sigStructure = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(protectedHeader)
                .payload((CBORByteArray) coseSign1.getPayload())
                .build();

        return verifySignature(keyAlgorithm, publicKey, sigStructure, coseSign1);
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

    private boolean verifySignature(String keyAlgorithm, PublicKey publicKey, SigStructure sigStructure, COSESign1 coseSign1) {
        String algorithm = getCoseAlgorithmString((int) coseSign1.getProtectedHeader().getAlg());
        try {
            Signature verifier;
            if (keyAlgorithm.equals(KeymanagerConstant.EC_KEY_TYPE)) {
                verifier = Signature.getInstance(AlgorithmInstanceEnum.getAlgoInstance(algorithm), ecKeyStore.getKeystoreProviderName());
                verifier.initVerify(publicKey);
                verifier.update(sigStructure.encode());
                return verifier.verify(convertRawECSignatureToDER(coseSign1.getSignature().getValue()));
            } else {
                verifier = Signature.getInstance(AlgorithmInstanceEnum.getAlgoInstance(algorithm));
                verifier.initVerify(publicKey);
                verifier.update(sigStructure.encode());
                return verifier.verify(coseSign1.getSignature().getValue());
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Error occurred while verifying signature.", e);
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
        try {
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
        } catch (IllegalArgumentException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Error occurred parsing hex string to byte array. Check provided data is hex or not.", e);
            throw new SignatureFailureException(SignatureErrorCode.DATA_PARSING_ERROR.getErrorCode(),
                    SignatureErrorCode.DATA_PARSING_ERROR.getErrorMessage(), e);
        }
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

    private static void setKidHeader(String keyId, CoseSignRequestDto requestDto, COSEProtectedHeaderBuilder protectedHeaderBuilder, COSEUnprotectedHeaderBuilder unprotectedHeaderBuilder) {
        if (keyId != null && Boolean.TRUE.equals(requestDto.getProtectedHeader().get("kid"))) {
            protectedHeaderBuilder.kid(keyId);
        } else if (keyId != null) {
            unprotectedHeaderBuilder.kid(keyId);
        }
    }
}
