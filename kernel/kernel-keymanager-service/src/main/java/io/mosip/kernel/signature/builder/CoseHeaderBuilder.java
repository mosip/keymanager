package io.mosip.kernel.signature.builder;

import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSEUnprotectedHeaderBuilder;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.exception.SignatureFailureException;

import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

public class CoseHeaderBuilder {
    private final SignatureCertificate certificateResponse;
    private final CoseSignRequestDto requestDto;
    private final Integer coseAlgorithm;
    private final KeymanagerUtil keymanagerUtil;
    private final Logger logger;

    public CoseHeaderBuilder(SignatureCertificate certificateResponse,
                             CoseSignRequestDto requestDto,
                             Integer coseAlgorithm,
                             KeymanagerUtil keymanagerUtil,
                             Logger logger) {
        this.certificateResponse = certificateResponse;
        this.requestDto = requestDto;
        this.coseAlgorithm = coseAlgorithm;
        this.keymanagerUtil = keymanagerUtil;
        this.logger = logger;
    }

    public COSEProtectedHeaderBuilder buildProtected() {
        COSEProtectedHeaderBuilder protectedHeaderBuilder = new COSEProtectedHeaderBuilder();
        Map<String, Object> protectedHeaderMap = requestDto.getProtectedHeader();

        if (coseAlgorithm != null) {
            protectedHeaderBuilder.alg(coseAlgorithm);
        }

        if (protectedHeaderMap == null || protectedHeaderMap.isEmpty()) {
            return protectedHeaderBuilder;
        }

        if (protectedHeaderMap.containsKey(SignatureConstant.COSE_HEADER_CRITICAL_PARAM)) {
            Object critValue = protectedHeaderMap.get(SignatureConstant.COSE_HEADER_CRITICAL_PARAM);
            List<Object> critList = parseCritHeader((String) critValue);
            protectedHeaderBuilder.crit(critList);
        }

        if (protectedHeaderMap.containsKey(SignatureConstant.JWS_HEADER_CONTENT_TYPE) || protectedHeaderMap.containsKey(SignatureConstant.COSE_HEADER_CONTENT_TYPE)) {
            Object contentType = protectedHeaderMap.getOrDefault(SignatureConstant.JWS_HEADER_CONTENT_TYPE, protectedHeaderMap.get(SignatureConstant.COSE_HEADER_CONTENT_TYPE));
            protectedHeaderBuilder.contentType((String) contentType);
        }

        X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
        if (protectedHeaderMap.containsKey(SignatureConstant.INCLUDE_CERTIFICATE_CHAIN)) {
            Object includeCertChainValue = protectedHeaderMap.get(SignatureConstant.INCLUDE_CERTIFICATE_CHAIN);
            if (includeCertChainValue instanceof Boolean) {
                boolean includeCertChain = (boolean) includeCertChainValue;
                if (includeCertChain) {
                    List<? extends Certificate> x5Chain = keymanagerUtil.getCertificateTrustPath(x509Certificate);
                    try {
                        protectedHeaderBuilder.x5chain((List<X509Certificate>) x5Chain);
                    } catch (CertificateEncodingException e) {
                        throw new SignatureFailureException(SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(),
                                SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorMessage(), e);
                    }
                }
            } else {
                logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: includeCertificateChain header value is not a boolean.");
            }
        } else if (protectedHeaderMap.containsKey(SignatureConstant.INCLUDE_CERTIFICATE)) {
            Object includeCertValue = protectedHeaderMap.get(SignatureConstant.INCLUDE_CERTIFICATE);
            if (includeCertValue instanceof Boolean) {
                boolean includeCert = (boolean) includeCertValue;
                if (includeCert) {
                    try {
                        protectedHeaderBuilder.x5chain(Collections.singletonList(x509Certificate));
                    } catch (CertificateEncodingException e) {
                        throw new SignatureFailureException(SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(),
                                SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorMessage(), e);
                    }
                }
            }
        }

        if (protectedHeaderMap.containsKey(SignatureConstant.INCLUDE_CERTIFICATE_HASH)) {
            Object includeCertHashValue = protectedHeaderMap.get(SignatureConstant.INCLUDE_CERTIFICATE_HASH);
            if (includeCertHashValue instanceof Boolean) {
                boolean includeCertHash = (boolean) includeCertHashValue;
                if (includeCertHash) {
                    try {
                        byte[] certHash = MessageDigest.getInstance(SignatureConstant.PSS_PARAM_SHA_256).digest(x509Certificate.getEncoded());
                        protectedHeaderBuilder.put(34, certHash);
                    } catch (Exception e) {
                        logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                                "Warning: error generating certificate hash for COSE protected header.");
                    }
                }
            } else {
                logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: includeCertHash header value is not a boolean.");
            }
        }

        if (protectedHeaderMap.containsKey(SignatureConstant.CERTIFICATE_URL)) {
            Object certificateUrlValue = protectedHeaderMap.get(SignatureConstant.CERTIFICATE_URL);
            if (certificateUrlValue instanceof String certificateUrl) {
                if (!certificateUrl.isEmpty()) {
                    protectedHeaderBuilder.put(35, certificateUrl);
                }
            } else {
                logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: certificateUrl header value is not a string.");
            }
        }

        if (protectedHeaderMap.containsKey(SignatureConstant.COSE_HEADER_IV)) {
            Object ivValue = protectedHeaderMap.get(SignatureConstant.COSE_HEADER_IV);
            if (ivValue instanceof String iv) {
                protectedHeaderBuilder.iv(iv.getBytes());
            }
        } else if (protectedHeaderMap.containsKey(SignatureConstant.COSE_HEADER_PARTIAL_IV)) {
            Object partialIVValue = protectedHeaderMap.get(SignatureConstant.COSE_HEADER_PARTIAL_IV);
            if (partialIVValue instanceof String partialIV) {
                protectedHeaderBuilder.partialIv(partialIV.getBytes());
            }
        }

        if (!protectedHeaderMap.isEmpty()) {
            for (Map.Entry<String, Object> entry : requestDto.getProtectedHeader().entrySet()) {
                if (!STANDARD_HEADER_KEYS.contains(entry.getKey()) && !CERTIFICATE_OBJECTS.contains(entry.getKey())) {
                    try {
                        protectedHeaderBuilder.put(entry.getKey(), entry.getValue());
                    } catch (Exception e) {
                        logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                                "Warning: error adding custom protected header: " + entry.getKey(), e);
                    }
                }
            }
        }

        return protectedHeaderBuilder;
    }

    public COSEUnprotectedHeaderBuilder buildUnprotected() {
        COSEUnprotectedHeaderBuilder unprotectedHeaderBuilder = new COSEUnprotectedHeaderBuilder();
        Map<String, Object> unprotectedHeaderMap = requestDto.getUnprotectedHeader();

        if (unprotectedHeaderMap == null || unprotectedHeaderMap.isEmpty()) {
            return unprotectedHeaderBuilder;
        }

        if (requestDto.getProtectedHeader() != null && !requestDto.getProtectedHeader().isEmpty()) {
            unprotectedHeaderMap = unprotectedHeaderMap.entrySet().stream()
                    .filter(entry -> !requestDto.getProtectedHeader().containsKey(entry.getKey()))
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        }

        if (unprotectedHeaderMap.containsKey(SignatureConstant.COSE_HEADER_CRITICAL_PARAM)) {
            Object critValue = unprotectedHeaderMap.get(SignatureConstant.COSE_HEADER_CRITICAL_PARAM);
            List<Object> critList = parseCritHeader((String) critValue);
            unprotectedHeaderBuilder.crit(critList);
        }

        if (unprotectedHeaderMap.containsKey(SignatureConstant.JWS_HEADER_CONTENT_TYPE) || unprotectedHeaderMap.containsKey(SignatureConstant.COSE_HEADER_CONTENT_TYPE)) {
            Object contentType = unprotectedHeaderMap.getOrDefault(SignatureConstant.JWS_HEADER_CONTENT_TYPE, unprotectedHeaderMap.get(SignatureConstant.COSE_HEADER_CONTENT_TYPE));
            unprotectedHeaderBuilder.contentType((String) contentType);
        }

        X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
        if (!requestDto.getProtectedHeader().containsKey(SignatureConstant.INCLUDE_CERTIFICATE_CHAIN) && !requestDto.getProtectedHeader().containsKey(SignatureConstant.INCLUDE_CERTIFICATE)) {
            if (unprotectedHeaderMap.containsKey(SignatureConstant.INCLUDE_CERTIFICATE_CHAIN)) {
                Object includeCertChainValue = unprotectedHeaderMap.get(SignatureConstant.INCLUDE_CERTIFICATE_CHAIN);
                if (includeCertChainValue instanceof Boolean) {
                    boolean includeCertChain = (boolean) includeCertChainValue;
                    if (includeCertChain) {
                        List<? extends Certificate> x5Chain = keymanagerUtil.getCertificateTrustPath(x509Certificate);
                        try {
                            unprotectedHeaderBuilder.x5chain((List<X509Certificate>) x5Chain);
                        } catch (CertificateEncodingException e) {
                            throw new SignatureFailureException(SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(),
                                    SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorMessage(), e);
                        }
                    }
                } else {
                    logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                            "Warning: includeCertificateChain header value is not a boolean.");
                }
            } else if (unprotectedHeaderMap.containsKey(SignatureConstant.INCLUDE_CERTIFICATE)) {
                Object includeCertValue = unprotectedHeaderMap.get(SignatureConstant.INCLUDE_CERTIFICATE);
                if (includeCertValue instanceof Boolean) {
                    boolean includeCert = (boolean) includeCertValue;
                    if (includeCert) {
                        try {
                            unprotectedHeaderBuilder.x5chain(Collections.singletonList(x509Certificate));
                        } catch (CertificateEncodingException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            }
        }

        if (unprotectedHeaderMap.containsKey(SignatureConstant.INCLUDE_CERTIFICATE_HASH)) {
            Object includeCertHashValue = unprotectedHeaderMap.get(SignatureConstant.INCLUDE_CERTIFICATE_HASH);
            if (includeCertHashValue instanceof Boolean) {
                boolean includeCertHash = (boolean) includeCertHashValue;
                if (includeCertHash) {
                    try {
                        byte[] certHash = MessageDigest.getInstance(SignatureConstant.PSS_PARAM_SHA_256).digest(x509Certificate.getEncoded());
                        unprotectedHeaderBuilder.put(34, certHash);
                    } catch (Exception e) {
                        logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                                "Warning: error generating certificate hash for COSE protected header.");
                    }
                }
            } else {
                logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: includeCertHash header value is not a boolean.");
            }
        }

        if (unprotectedHeaderMap.containsKey(SignatureConstant.CERTIFICATE_URL)) {
            Object certificateUrlValue = unprotectedHeaderMap.get(SignatureConstant.CERTIFICATE_URL);
            if (certificateUrlValue instanceof String certificateUrl) {
                if (!certificateUrl.isEmpty()) {
                    unprotectedHeaderBuilder.put(35, certificateUrl);
                }
            } else {
                logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: certificateUrl header value is not a string.");
            }
        }

        if (unprotectedHeaderMap.containsKey(SignatureConstant.COSE_HEADER_IV)) {
            Object ivValue = unprotectedHeaderMap.get(SignatureConstant.COSE_HEADER_IV);
            if (ivValue instanceof String iv) {
                unprotectedHeaderBuilder.iv(iv.getBytes());
            }
        } else if (unprotectedHeaderMap.containsKey(SignatureConstant.COSE_HEADER_PARTIAL_IV)) {
            Object partialIVValue = unprotectedHeaderMap.get(SignatureConstant.COSE_HEADER_PARTIAL_IV);
            if (partialIVValue instanceof String partialIV) {
                unprotectedHeaderBuilder.partialIv(partialIV.getBytes());
            }
        }

        if (!unprotectedHeaderMap.isEmpty()) {
            for (Map.Entry<String, Object> entry : unprotectedHeaderMap.entrySet()) {
                if (!STANDARD_HEADER_KEYS.contains(entry.getKey()) && !CERTIFICATE_OBJECTS.contains(entry.getKey())) {
                    try {
                        unprotectedHeaderBuilder.put(entry.getKey(), entry.getValue());
                    } catch (Exception e) {
                        logger.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                                "Warning: error adding custom unprotected header: " + entry.getKey(), e);
                    }
                }
            }
        }

        return unprotectedHeaderBuilder;
    }

    public static List<Object> parseCritHeader(String critValue) {
        if (critValue == null || critValue.isBlank()) {
            return Collections.emptyList();
        }
        return Arrays.stream(critValue.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .distinct()
                .map(s -> (Object) s)
                .collect(Collectors.toList());
    }

    private static final Set<Object> STANDARD_HEADER_KEYS = Set.of("alg", "crit", "content-type", "cty", "kid", "iv", "x5c", "x5t",
            "x5t#S256", "x5u", "content", "partialIV", "partial-iv", 1, 2, 3, 4, 5, 6, 32, 33, 34, 35);

    private static final Set<Object> CERTIFICATE_OBJECTS = Set.of("includeCertificate", "includeCertificateChain", "includeCertificateHash", "certificateUrl");
} 