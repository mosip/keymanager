package io.mosip.kernel.signature.service.impl;

import com.authlete.cbor.*;
import com.authlete.cose.*;
import com.authlete.cose.constants.COSEAlgorithms;
import com.authlete.cwt.constants.CWTClaims;
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

    @Value("${mosip.kernel.keymanager.signature.cwt.verify.iss:}")
    private String verifyIss;

    @Value("${mosip.kernel.keymanager.signature.cwt.verify.sub:}")
    private String verifySub;

    @Value("${mosip.kernel.keymanager.signature.cwt.verify.iss.enable:false}")
    private boolean issVerifyEnable;

    @Value("${mosip.kernel.keymanager.signature.cwt.verify.sub.enable:false}")
    private boolean subVerifyEnable;

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
        CBORTaggedItem sign1Tagged = new CBORTaggedItem(SignatureConstant.COSE_SIGN1_TAG, coseItem);

        if (isCwt) {
            CBORTaggedItem cwtTagged = new CBORTaggedItem(SignatureConstant.CWT_SIGN_TAG, sign1Tagged);
            return cwtTagged.encode();
        } else {
            return sign1Tagged.encode();
        }
    }

    @Override
    public CoseSignVerifyResponseDto coseVerify1(CoseSignVerifyRequestDto requestDto) {
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

            byte[] coseData = signatureUtil.decodeHex(coseHexdata);
            CBORDecoder cborDecoder = new CBORDecoder(coseData);
            CBORTaggedItem cborTaggedItem = (CBORTaggedItem) cborDecoder.next();
            if ((int)cborTaggedItem.getTagNumber() != SignatureConstant.COSE_SIGN1_TAG) {
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

    public String getKeyId(String kidPrepend, SignatureCertificate certificateResponse, CoseSignRequestDto requestDto, boolean includeKeyId) {

        if ((requestDto.getProtectedHeader() != null && requestDto.getProtectedHeader().containsKey(SignatureConstant.COSE_HEADER_KID)) ||
                (requestDto.getUnprotectedHeader() != null && requestDto.getUnprotectedHeader().containsKey(SignatureConstant.COSE_HEADER_KID))) {
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
        boolean protectedKid = requestDto.getProtectedHeader() != null && requestDto.getProtectedHeader().containsKey(SignatureConstant.COSE_HEADER_KID);
        if (keyId != null && protectedKid) {
            protectedHeaderBuilder.kid(keyId);
        } else if (keyId != null) {
            unprotectedHeaderBuilder.kid(keyId);
        }
    }

    @Override
    public CoseSignResponseDto cwtSign(CWTSignRequestDto requestDto) {
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                "CWT Sign Request");

        if (!cryptomanagerUtil.hasKeyAccess(requestDto.getApplicationId())) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                    "Signing Data is not allowed for the authenticated user for the provided application id." + " App Id: " + requestDto.getApplicationId());
            throw new RequestException(SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorCode(),
                    SignatureErrorCode.SIGN_NOT_ALLOWED.getErrorMessage());
        }

        String b64Payload = requestDto.getPayload();
        if (!SignatureUtil.isDataValid(b64Payload) && !SignatureUtil.isDataValid(requestDto.getClaim169Payload())) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                    "Provided Payload is invalid.");
            throw new RequestException(SignatureErrorCode.INVALID_INPUT.getErrorCode(),
                    SignatureErrorCode.INVALID_INPUT.getErrorMessage());
        }

        String timestamp = DateUtils.getUTCCurrentDateTimeString();
        String applicationId = requestDto.getApplicationId();
        String referenceId = requestDto.getReferenceId();
        if (!keymanagerUtil.isValidApplicationId(applicationId)) {
            applicationId = signApplicationid;
            referenceId = signRefid;
        }

        SignatureCertificate certificateResponse = keymanagerService.getSignatureCertificate(applicationId, Optional.of(referenceId), timestamp);
        byte[] cborClaimsPayload = signatureUtil.buildCWTClaimSet(requestDto);
        CoseSignRequestDto coseSignRequestDto = buildCoseSignRequestDto(requestDto);
        String signedData = signCose1(cborClaimsPayload, certificateResponse, referenceId, coseSignRequestDto, true);

        CoseSignResponseDto responseDto = new CoseSignResponseDto();
        responseDto.setSignedData(signedData);
        responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                "CWT Sign Request Successful.");
        return responseDto;
    }

    private static CoseSignRequestDto buildCoseSignRequestDto(CWTSignRequestDto requestDto) {
        CoseSignRequestDto coseSignRequestDto = new CoseSignRequestDto();
        coseSignRequestDto.setPayload(requestDto.getPayload());
        coseSignRequestDto.setApplicationId(requestDto.getApplicationId());
        coseSignRequestDto.setReferenceId(requestDto.getReferenceId());
        coseSignRequestDto.setProtectedHeader(requestDto.getProtectedHeader());
        coseSignRequestDto.setUnprotectedHeader(requestDto.getUnprotectedHeader());
        coseSignRequestDto.setAlgorithm(requestDto.getAlgorithm());
        return coseSignRequestDto;
    }

    private static CoseSignVerifyRequestDto buildCoseSignVerifyRequestDto(CWTVerifyRequestDto requestDto) {
        CoseSignVerifyRequestDto coseSignVerifyRequestDto = new CoseSignVerifyRequestDto();
        coseSignVerifyRequestDto.setCoseSignedData(requestDto.getCoseSignedData());
        coseSignVerifyRequestDto.setApplicationId(requestDto.getApplicationId());
        coseSignVerifyRequestDto.setReferenceId(requestDto.getReferenceId());
        coseSignVerifyRequestDto.setCertificateData(requestDto.getCertificateData());
        coseSignVerifyRequestDto.setValidateTrust(requestDto.getValidateTrust());
        coseSignVerifyRequestDto.setDomain(requestDto.getDomain());
        return coseSignVerifyRequestDto;
    }

    @Override
    public CoseSignVerifyResponseDto cwtVerify(CWTVerifyRequestDto requestDto) {
        LOGGER.info(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                "CWT Verify Request");

        try {
            String cwtHexData = requestDto.getCoseSignedData();
            if (!SignatureUtil.isDataValid(cwtHexData)) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Provided CWT data is invalid.");
                throw new RequestException(SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorCode(),
                        SignatureErrorCode.INVALID_VERIFY_INPUT.getErrorMessage());
            }

            String reqCertData = SignatureUtil.isDataValid(requestDto.getCertificateData()) ? requestDto.getCertificateData() : null;
            String applicationId = requestDto.getApplicationId();
            String referenceId = requestDto.getReferenceId();
            if (!keymanagerUtil.isValidApplicationId(applicationId)) {
                applicationId = signApplicationid;
                referenceId = signRefid;
            }

            byte[] cwtData = signatureUtil.decodeHex(cwtHexData);
            CBORDecoder cborDecoder = new CBORDecoder(cwtData);
            CBORTaggedItem outerCborTaggedItem = (CBORTaggedItem) cborDecoder.next();
            if ((int) outerCborTaggedItem.getTagNumber() != SignatureConstant.CWT_SIGN_TAG ) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Provided Data is not CWT or missing CWT Tag." + " CWT Tag Number: " + outerCborTaggedItem.getTagNumber());
                throw new RequestException(SignatureErrorCode.INVALID_CWT_INPUT.getErrorCode(),
                        SignatureErrorCode.INVALID_CWT_INPUT.getErrorMessage());
            }

            CBORTaggedItem innerTaggedItem = (CBORTaggedItem) outerCborTaggedItem.getTagContent();
            if ((int) innerTaggedItem.getTagNumber() != SignatureConstant.COSE_SIGN1_TAG) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Provided CWT data does not have COSE Sign1 Array tag (or) is not signed by COSE Sign1." + " COSE Sign1 Tag Number: " + innerTaggedItem.getTagNumber());
                throw new RequestException(SignatureErrorCode.INVALID_COSE_SIGN1_INPUT.getErrorCode(),
                        SignatureErrorCode.INVALID_COSE_SIGN1_INPUT.getErrorMessage());
            }

            COSESign1 cwtSign1 = (COSESign1) innerTaggedItem.getTagContent();
            Map<Object, Object> claimsMap = signatureUtil.constructMapfromCoseSign1Payload(cwtSign1);
            basicCWTChecks(claimsMap, requestDto);
            boolean signatureValid = verifyCoseSignature(cwtSign1, reqCertData, applicationId, referenceId);

            CoseSignVerifyResponseDto responseDto = new CoseSignVerifyResponseDto();
            responseDto.setSignatureValid(signatureValid);
            responseDto.setMessage(signatureValid ? SignatureConstant.VALIDATION_SUCCESSFUL : SignatureConstant.VALIDATION_FAILED);
            CoseSignVerifyRequestDto coseSignVerifyRequestDto = buildCoseSignVerifyRequestDto(requestDto);
            responseDto.setTrustValid(validateTrustForCose(applicationId, referenceId, cwtSign1, reqCertData, coseSignVerifyRequestDto));
            return responseDto;
        } catch (IOException e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Error occurred while verifying CWT data.", e);
            throw new RequestException(SignatureErrorCode.COSE_VERIFY_ERROR.getErrorCode(),
                    SignatureErrorCode.COSE_VERIFY_ERROR.getErrorMessage(), e);
        }
    }

    private void basicCWTChecks(Map<Object, Object> payloadMap, CWTVerifyRequestDto requestDto) {

        String issuer = requestDto.getIssuer() != null ? requestDto.getIssuer() : verifyIss;
        String subject = requestDto.getSubject() != null ? requestDto.getSubject() : verifySub;

        if (payloadMap == null || payloadMap.isEmpty()) {
            throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
                    SignatureErrorCode.INVALID_JSON.getErrorMessage());
        }

        if (payloadMap.containsKey(CWTClaims.NBF)) {
            long nbfSeconds = ((Number) payloadMap.get(CWTClaims.NBF)).longValue();
            Date nbfDate = new Date(nbfSeconds * 1000);
            if (!signatureUtil.isNotBeforeDateValid(nbfDate)) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Provided CWT Sign is not ACTIVATED. NotBeforeDate is in the future.");
                throw new RequestException(SignatureErrorCode.FUTURE_DATE_ERROR.getErrorCode(),
                        SignatureErrorCode.FUTURE_DATE_ERROR.getErrorMessage());
            }
        }

        if (payloadMap.containsKey(CWTClaims.EXP)) {
            long expSeconds = ((Number) payloadMap.get(CWTClaims.EXP)).longValue();
            Date expDate = new Date(expSeconds * 1000);
            if (!signatureUtil.isExpireDateValid(expDate)) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Provided CWT Sign is EXPIRED. ExpiryDate is in the past.");
                throw new RequestException(SignatureErrorCode.EXPIRE_DATE_ERROR.getErrorCode(),
                        SignatureErrorCode.EXPIRE_DATE_ERROR.getErrorMessage());
            }
        }

        if (issVerifyEnable) {
            String cwtIss = payloadMap.get(CWTClaims.ISS) != null ? payloadMap.get(CWTClaims.ISS).toString() : null;
            if (cwtIss == null) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Issuer claim is missing in the token payload." + " Issuer: " + null);
                throw new RequestException(SignatureErrorCode.CLAIM_NOT_FOUND.getErrorCode(),
                        SignatureErrorCode.CLAIM_NOT_FOUND.getErrorMessage().replace("{claim}", "Issuer"));
            } else {
                if (!cwtIss.equals(issuer)) {
                    LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                            "Issuer claim value does not match." + " Expected Issuer: " + issuer + ", Provided Issuer: " + cwtIss);
                    throw new RequestException(SignatureErrorCode.CLAIM_NOT_MATCHED.getErrorCode(),
                            SignatureErrorCode.CLAIM_NOT_MATCHED.getErrorMessage().replace("{claim}", "Issuer"));
                }
            }
        }

        if (subVerifyEnable) {
            String cwtSub = payloadMap.get(CWTClaims.SUB) != null ? payloadMap.get(CWTClaims.SUB).toString() : null;
            if (cwtSub == null) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                        "Subject claim is missing in the token payload." + " Subject: " + null);
                throw new RequestException(SignatureErrorCode.CLAIM_NOT_FOUND.getErrorCode(),
                        SignatureErrorCode.CLAIM_NOT_FOUND.getErrorMessage().replace("{claim}", "Subject"));
            } else {
                if (!cwtSub.equals(subject)) {
                    LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                            "Subject claim value does not match." + " Expected Subject: " + subject + ", Provided Subject: " + cwtSub);
                    throw new RequestException(SignatureErrorCode.CLAIM_NOT_MATCHED.getErrorCode(),
                            SignatureErrorCode.CLAIM_NOT_MATCHED.getErrorMessage().replace("{claim}", "Subject"));
                }
            }
        }
    }
}
