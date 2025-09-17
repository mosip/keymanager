package io.mosip.kernel.signature.builder;

import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSEUnprotectedHeaderBuilder;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.signature.constant.SignatureConstant;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import io.mosip.kernel.signature.util.SignatureUtil;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class CoseHeaderBuilder {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(CoseHeaderBuilder.class);

    private static final Set<Object> STANDARD_HEADER_KEYS = Set.of("alg", "crit", "content-type", "cty", "kid", "iv", "x5c", "x5t",
            "x5t#S256", "x5u", "content", "partialIV", "partial-iv", 1, 2, 3, 4, 5, 6, 32, 33, 34, 35);

    private static final Set<Object> CERTIFICATE_OBJECTS = Set.of("includeCertificate", "includeCertificateChain", "includeCertificateHash", "certificateUrl");

    public COSEProtectedHeaderBuilder buildProtectedHeader(SignatureCertificate certificateResponse, CoseSignRequestDto requestDto, Integer coseAlgorithm, KeymanagerUtil keymanagerUtil) {
        COSEProtectedHeaderBuilder protectedHeaderBuilder = new COSEProtectedHeaderBuilder();
        Map<String, Object> protectedHeaderMap = requestDto.getProtectedHeader();

        if (coseAlgorithm != null) {
            protectedHeaderBuilder.alg(coseAlgorithm);
        }

        if (protectedHeaderMap == null || protectedHeaderMap.isEmpty()) {
            return protectedHeaderBuilder;
        }

        List<Object> critList = extractCritList(protectedHeaderMap);
        if (!critList.isEmpty()) {
            protectedHeaderBuilder.crit(critList);
        }

        String contentType = extractContentType(protectedHeaderMap);
        if (contentType != null) {
            protectedHeaderBuilder.contentType(contentType);
        }

        // X.509 chain or single certificate
        List<X509Certificate> x5c = getX509CertificateList(certificateResponse, protectedHeaderMap, keymanagerUtil);
        if (x5c != null && !x5c.isEmpty()) {
            try {
                protectedHeaderBuilder.x5chain(x5c);
            } catch (CertificateEncodingException e) {
                throw new SignatureFailureException(SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(),
                        SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorMessage(), e);
            }
        }

        // Certificate hash
        byte[] certHash = computeCertHashIfRequested(certificateResponse, protectedHeaderMap);
        if (certHash != null) {
            protectedHeaderBuilder.put(34, certHash);
        }

        // Certificate URL
        String certificateUrl = extractCertificateUrl(protectedHeaderMap);
        if (certificateUrl != null && !certificateUrl.isEmpty()) {
            protectedHeaderBuilder.put(35, certificateUrl);
        }

        // IV or Partial IV
        byte[] ivBytes = extractIvBytes(protectedHeaderMap);
        if (ivBytes != null) {
            protectedHeaderBuilder.iv(ivBytes);
        } else {
            byte[] partialIvBytes = extractPartialIvBytes(protectedHeaderMap);
            if (partialIvBytes != null) {
                protectedHeaderBuilder.partialIv(partialIvBytes);
            }
        }

        // Custom headers
        Map<String, Object> customHeaders = extractCustomHeaders(protectedHeaderMap);
        for (Map.Entry<String, Object> entry : customHeaders.entrySet()) {
            try {
                protectedHeaderBuilder.put(entry.getKey(), entry.getValue());
            } catch (Exception e) {
                LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: error adding custom protected header: " + entry.getKey(), e);
            }
        }

        return protectedHeaderBuilder;
    }

    public COSEUnprotectedHeaderBuilder buildUnprotectedHeader(SignatureCertificate certificateResponse, CoseSignRequestDto requestDto, KeymanagerUtil keymanagerUtil) {
        COSEUnprotectedHeaderBuilder unprotectedHeaderBuilder = new COSEUnprotectedHeaderBuilder();
        Map<String, Object> unprotectedHeaderMap = requestDto.getUnprotectedHeader();

        if (unprotectedHeaderMap == null || unprotectedHeaderMap.isEmpty()) {
            return unprotectedHeaderBuilder;
        }

        unprotectedHeaderMap = SignatureUtil.filterMapEntries(requestDto.getProtectedHeader(), unprotectedHeaderMap);

        List<Object> critList = extractCritList(unprotectedHeaderMap);
        if (!critList.isEmpty()) {
            unprotectedHeaderBuilder.crit(critList);
        }

        String contentType = extractContentType(unprotectedHeaderMap);
        if (contentType != null) {
            unprotectedHeaderBuilder.contentType(contentType);
        }

        // X.509 chain or single certificate (only if not requested in protected headers)
        List<X509Certificate> x5c = getX509CertificateList(certificateResponse, unprotectedHeaderMap, keymanagerUtil);
        if (x5c != null && !x5c.isEmpty()) {
            try {
                unprotectedHeaderBuilder.x5chain(x5c);
            } catch (CertificateEncodingException e) {
                throw new SignatureFailureException(SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorCode(),
                        SignatureErrorCode.INTERNAL_SERVER_ERROR.getErrorMessage(), e);
            }
        }


        // Certificate hash
        byte[] certHash = computeCertHashIfRequested(certificateResponse, unprotectedHeaderMap);
        if (certHash != null) {
            unprotectedHeaderBuilder.put(34, certHash);
        }

        // Certificate URL
        String certificateUrl = extractCertificateUrl(unprotectedHeaderMap);
        if (certificateUrl != null && !certificateUrl.isEmpty()) {
            unprotectedHeaderBuilder.put(35, certificateUrl);
        }

        // IV or Partial IV
        byte[] ivBytes = extractIvBytes(unprotectedHeaderMap);
        if (ivBytes != null) {
            unprotectedHeaderBuilder.iv(ivBytes);
        } else {
            byte[] partialIvBytes = extractPartialIvBytes(unprotectedHeaderMap);
            if (partialIvBytes != null) {
                unprotectedHeaderBuilder.partialIv(partialIvBytes);
            }
        }

        // Custom headers
        Map<String, Object> customHeaders = extractCustomHeaders(unprotectedHeaderMap);
        for (Map.Entry<String, Object> entry : customHeaders.entrySet()) {
            try {
                unprotectedHeaderBuilder.put(entry.getKey(), entry.getValue());
            } catch (Exception e) {
                LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: error adding custom unprotected header: " + entry.getKey(), e);
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

    private static List<Object> extractCritList(Map<String, Object> headerMap) {
        if (headerMap.containsKey(SignatureConstant.COSE_HEADER_CRITICAL_PARAM)) {
            Object critValue = headerMap.get(SignatureConstant.COSE_HEADER_CRITICAL_PARAM);
            return parseCritHeader((String) critValue);
        }
        return Collections.emptyList();
    }

    private static String extractContentType(Map<String, Object> headerMap) {
        if (headerMap.containsKey(SignatureConstant.JWS_HEADER_CONTENT_TYPE) || headerMap.containsKey(SignatureConstant.COSE_HEADER_CONTENT_TYPE)) {
            Object contentType = headerMap.getOrDefault(SignatureConstant.JWS_HEADER_CONTENT_TYPE,
                    headerMap.get(SignatureConstant.COSE_HEADER_CONTENT_TYPE));
            return (String) contentType;
        }
        return null;
    }

    private static List<X509Certificate> getX509CertificateList(SignatureCertificate certificateResponse, Map<String, Object> headerMap, KeymanagerUtil keymanagerUtil) {
        X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];

        if (headerMap.containsKey(SignatureConstant.INCLUDE_CERTIFICATE_CHAIN)) {
            Object includeCertChainValue = headerMap.get(SignatureConstant.INCLUDE_CERTIFICATE_CHAIN);
            if (includeCertChainValue instanceof Boolean) {
                boolean includeCertChain = (boolean) includeCertChainValue;
                if (includeCertChain) {
                    List<? extends Certificate> x5Chain = keymanagerUtil.getCertificateTrustPath(x509Certificate);
                    return convertToX509CertificateList(x5Chain);
                }
            } else {
                LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: includeCertificateChain header value is not a boolean.");
            }
        }

        if (headerMap.containsKey(SignatureConstant.INCLUDE_CERTIFICATE)) {
            Object includeCertValue = headerMap.get(SignatureConstant.INCLUDE_CERTIFICATE);
            if (includeCertValue instanceof Boolean) {
                boolean includeCert = (boolean) includeCertValue;
                if (includeCert) {
                    return Collections.singletonList(x509Certificate);
                }
            }
        }
        return null;
    }

    private static List<X509Certificate> convertToX509CertificateList(List<? extends Certificate> certificates) {
        if (certificates == null || certificates.isEmpty()) {
            return Collections.emptyList();
        }
        return certificates.stream()
                .filter(Objects::nonNull)
                .filter(c -> c instanceof X509Certificate)
                .map(c -> (X509Certificate) c)
                .collect(Collectors.toList());
    }

    private static byte[] computeCertHashIfRequested(SignatureCertificate certificateResponse, Map<String, Object> headerMap) {
        X509Certificate x509Certificate = certificateResponse.getCertificateEntry().getChain()[0];
        if (headerMap.containsKey(SignatureConstant.INCLUDE_CERTIFICATE_HASH)) {
            Object includeCertHashValue = headerMap.get(SignatureConstant.INCLUDE_CERTIFICATE_HASH);
            if (includeCertHashValue instanceof Boolean) {
                boolean includeCertHash = (boolean) includeCertHashValue;
                if (includeCertHash) {
                    try {
                        return MessageDigest.getInstance(SignatureConstant.PSS_PARAM_SHA_256).digest(x509Certificate.getEncoded());
                    } catch (Exception e) {
                        LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                                "Warning: error generating certificate hash for COSE protected header.");
                    }
                }
            } else {
                LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: includeCertHash header value is not a boolean.");
            }
        }
        return null;
    }

    private static String extractCertificateUrl(Map<String, Object> headerMap) {
        if (headerMap.containsKey(SignatureConstant.CERTIFICATE_URL)) {
            Object certificateUrlValue = headerMap.get(SignatureConstant.CERTIFICATE_URL);
            if (certificateUrlValue instanceof String) {
                return (String) certificateUrlValue;
            } else {
                LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Warning: certificateUrl header value is not a string.");
            }
        }
        return null;
    }

    private static byte[] extractIvBytes(Map<String, Object> headerMap) {
        if (headerMap.containsKey(SignatureConstant.COSE_HEADER_IV)) {
            Object ivValue = headerMap.get(SignatureConstant.COSE_HEADER_IV);
            if (ivValue instanceof String) {
                return ((String) ivValue).getBytes();
            }
        }
        return null;
    }

    private static byte[] extractPartialIvBytes(Map<String, Object> headerMap) {
        if (headerMap.containsKey(SignatureConstant.COSE_HEADER_PARTIAL_IV)) {
            Object partialIVValue = headerMap.get(SignatureConstant.COSE_HEADER_PARTIAL_IV);
            if (partialIVValue instanceof String) {
                return ((String) partialIVValue).getBytes();
            }
        }
        return null;
    }

    private static Map<String, Object> extractCustomHeaders(Map<String, Object> headerMap) {
        if (headerMap == null || headerMap.isEmpty()) {
            return Collections.emptyMap();
        }
        return headerMap.entrySet().stream()
                .filter(entry -> !STANDARD_HEADER_KEYS.contains(entry.getKey()) && !CERTIFICATE_OBJECTS.contains(entry.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}