package io.mosip.kernel.signature.util;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;
import io.mosip.kernel.signature.constant.SignatureErrorCode;
import io.mosip.kernel.signature.dto.CWTSignRequestDto;
import io.mosip.kernel.signature.exception.RequestException;
import io.mosip.kernel.signature.exception.SignatureFailureException;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.HMACUtils2;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.signature.constant.SignatureConstant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.Arrays;
import com.nimbusds.jose.JOSEObjectType;

/**
 * Utility class for Signature Service
 * 
 * @author Mahammed Taheer
 * @since 1.2.0-SNAPSHOT
 *
 */
@Component
public class SignatureUtil {

	@Autowired
	KeymanagerUtil keymanagerUtil;

    @Autowired
    PartnerCertificateManagerService partnerCertificateManagerService;

    @Value("${mosip.kernel.keymanager.signature.cwt.sign.iss:}")
    private String signIss;

    @Value("${mosip.kernel.keymanager.signature.cwt.exp:180}")
    private int expInDays;

    @Value("${mosip.kernel.keymanager.signature.cwt.nbf:0}")
    private int nbfInDays;

    @Value("${mosip.kernel.partner.trust.validate.domain.name:TRUST}")
    private String trustDomain;

	private static final Logger LOGGER = KeymanagerLogger.getLogger(SignatureUtil.class);
	private static ObjectMapper mapper = JsonMapper.builder().addModule(new AfterburnerModule()).build();

	public static boolean isDataValid(String anyData) {
		return anyData != null && !anyData.trim().isEmpty();
	}

	public static boolean isJsonValid(String jsonInString) {
		try {
			mapper.readTree(jsonInString);
			return true;
		} catch (IOException e) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided JSON Data to sign is invalid.");
		}
		return false;
	}

	public static boolean isIncludeAttrsValid(Boolean includes) {
		if (Objects.isNull(includes)) {
			return SignatureConstant.DEFAULT_INCLUDES;
		}
		return includes;
	}

	public static boolean isCertificateDatesValid(X509Certificate x509Cert) {

		try {
			Date currentDate = Date.from(DateUtils.getUTCCurrentDateTime().atZone(ZoneId.systemDefault()).toInstant());
			x509Cert.checkValidity(currentDate);
			return true;
		} catch (CertificateExpiredException | CertificateNotYetValidException exp) {
			LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate dates are not valid.");
		}
		try {
			// Checking both system default timezone & UTC Offset timezone. Issue found in
			// reg-client during trust validation.
			x509Cert.checkValidity();
			return true;
		} catch (CertificateExpiredException | CertificateNotYetValidException exp) {
			LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate dates are not valid.");
		}
		return false;
	}

	public static JWSHeader getJWSHeader(String signAlgorithm, boolean b64JWSHeaderParam, boolean includeCertificate, 
			boolean includeCertHash, String certificateUrl, X509Certificate x509Certificate, String uniqueIdentifier, 
			boolean includeKeyId, String kidPrepend) {

		JWSAlgorithm jwsAlgorithm = switch (signAlgorithm) {
            case SignatureConstant.JWS_RS256_SIGN_ALGO_CONST -> JWSAlgorithm.RS256;
            case SignatureConstant.JWS_ES256_SIGN_ALGO_CONST -> JWSAlgorithm.ES256;
            case SignatureConstant.JWS_ES256K_SIGN_ALGO_CONST -> JWSAlgorithm.ES256K;
            case SignatureConstant.JWS_EDDSA_SIGN_ALGO_CONST -> JWSAlgorithm.EdDSA;
            default -> JWSAlgorithm.PS256;
        };

        JWSHeader.Builder jwsHeaderBuilder = new JWSHeader.Builder(jwsAlgorithm);

		if (!b64JWSHeaderParam) 
			jwsHeaderBuilder = jwsHeaderBuilder.base64URLEncodePayload(false)
								.criticalParams(Collections.singleton(SignatureConstant.B64));

		if (includeCertificate) {
			try {
				Base64 signCert = Base64.encode(x509Certificate.getEncoded());
				List<Base64> x5c = new ArrayList<>();
				x5c.add(signCert);
				jwsHeaderBuilder = jwsHeaderBuilder.x509CertChain(x5c);
			} catch (CertificateEncodingException e) {
				// ignore this exception.
				LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate not able to parse while adding to jws header.");
			}
		}
		
		if (includeCertHash) {
			try {
				jwsHeaderBuilder = jwsHeaderBuilder.x509CertSHA256Thumbprint(Base64URL.encode(DigestUtils.sha256(x509Certificate.getEncoded())));
			} catch (CertificateEncodingException e) {
				// ignore this exception.
				LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate not able to parse while adding to jws header.");
			}
		}

		if (Objects.nonNull(certificateUrl)) {
			try {
				jwsHeaderBuilder.x509CertURL(new URI(certificateUrl));
			} catch (URISyntaxException e) {
				// ignore this exception.
				LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate URI not able to parse while adding to jws header.");
			}
		}

		String keyId = convertHexToBase64(uniqueIdentifier);
		if (includeKeyId && Objects.nonNull(keyId)) {
			jwsHeaderBuilder.keyID(kidPrepend.concat(keyId));
		}

		return jwsHeaderBuilder.build();
	}

	public static byte[] buildSignData(JWSHeader jwsHeader, byte[] actualDataToSign) {

		byte[] jwsHeaderBytes = jwsHeader.toBase64URL().toString().getBytes(StandardCharsets.UTF_8);
		byte[] jwsSignData = new byte[jwsHeaderBytes.length + actualDataToSign.length + 1];
		System.arraycopy(jwsHeaderBytes, 0, jwsSignData, 0, jwsHeaderBytes.length);
		jwsSignData[jwsHeaderBytes.length] = (byte) '.';
		System.arraycopy(actualDataToSign, 0, jwsSignData, jwsHeaderBytes.length + 1, actualDataToSign.length);
		return jwsSignData;
	}

	public static String convertHexToBase64(String anyHexString) {
		try {
			
			return CryptoUtil.encodeToURLSafeBase64(HMACUtils2.generateHash(Hex.decodeHex(anyHexString)));
		} catch (DecoderException | NoSuchAlgorithmException e) {
			// ignore this exception.
			LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
			"Warning thrown when converting hex data to base64 encoded data.");
			// not throwing exception, as this function is added to include kid in jwt signature.
			// in case any error in conversion kid will not be added in jwt header.
		}
		return null;
	}

	public static String getSignAlgorithm(String referenceId) {
		if (referenceId == null || referenceId.isBlank()) return SignatureConstant.JWS_PS256_SIGN_ALGO_CONST;
		else return switch (referenceId) {
			case SignatureConstant.EC_SECP256R1_SIGN -> SignatureConstant.JWS_ES256_SIGN_ALGO_CONST;
			case SignatureConstant.EC_SECP256K1_SIGN -> SignatureConstant.JWS_ES256K_SIGN_ALGO_CONST;
			case SignatureConstant.ED25519_SIGN -> SignatureConstant.JWS_EDDSA_SIGN_ALGO_CONST;
			default -> SignatureConstant.JWS_PS256_SIGN_ALGO_CONST;
		};
	}

	public static String getIssuerFromPayload(String jsonPayload) {
		try {
			JsonNode jsonNode = mapper.readTree(jsonPayload);

			if (jsonNode.has(SignatureConstant.ISSUER)) {
				return jsonNode.get(SignatureConstant.ISSUER).asText();
			} else {
				LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.ISSUER, SignatureConstant.BLANK,
						"Missing 'iss' field in provided JSON data.");
				return SignatureConstant.BLANK;
			}
		} catch (IOException e) {
			LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.JWT_SIGN, SignatureConstant.BLANK,
					"Provided JSON Data to sign is invalid.");
			return SignatureConstant.BLANK;
		}
	}

	public JWSHeader getJWSHeaderV2(String signAlgorithm, boolean b64JWSHeaderParam, boolean includeCertificateChain,
										 boolean includeCertHash, String certificateUrl, X509Certificate x509Certificate, String uniqueIdentifier,
										 boolean includeKeyId, String kidPrepend, Map<String, String> additionalHeaders) {

		JWSAlgorithm jwsAlgorithm = switch (signAlgorithm) {
			case SignatureConstant.JWS_RS256_SIGN_ALGO_CONST -> JWSAlgorithm.RS256;
			case SignatureConstant.JWS_ES256_SIGN_ALGO_CONST -> JWSAlgorithm.ES256;
			case SignatureConstant.JWS_ES256K_SIGN_ALGO_CONST -> JWSAlgorithm.ES256K;
			case SignatureConstant.JWS_EDDSA_SIGN_ALGO_CONST -> JWSAlgorithm.EdDSA;
			default -> JWSAlgorithm.PS256;
		};

		JWSHeader.Builder jwsHeaderBuilder = new JWSHeader.Builder(jwsAlgorithm);

		if (!b64JWSHeaderParam)
			jwsHeaderBuilder = jwsHeaderBuilder.base64URLEncodePayload(false)
					.criticalParams(Collections.singleton(SignatureConstant.B64));

		List<? extends Certificate> certificateChain = getCertificateTrustChain(x509Certificate);

		if (includeCertificateChain) {
			List<Base64> x5c = buildX509CertChain((List<X509Certificate>) certificateChain);
			jwsHeaderBuilder = jwsHeaderBuilder.x509CertChain(x5c);
		}

		if (includeCertHash) {
			Base64URL certThumbprint = getCertificateSHA256Thumbprint(x509Certificate);
			if (certThumbprint != null) {
				jwsHeaderBuilder = jwsHeaderBuilder.x509CertSHA256Thumbprint(certThumbprint);
			}
		}

		if (Objects.nonNull(certificateUrl)) {
			try {
				jwsHeaderBuilder.x509CertURL(new URI(certificateUrl));
			} catch (URISyntaxException e) {
				// ignore this exception.
				LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
						"Warning thrown when certificate URI not able to parse while adding to jws header.");
			}
		}

		jwsHeaderBuilder = addCustomHeaders(additionalHeaders, jwsHeaderBuilder);

		String finalKeyId = buildFinalKeyId(uniqueIdentifier, includeKeyId, additionalHeaders, kidPrepend);
		if (finalKeyId != null) {
			jwsHeaderBuilder.keyID(finalKeyId);
		}

		jwsHeaderBuilder = addRegisteredJWSHeaders(additionalHeaders, jwsHeaderBuilder);
		return jwsHeaderBuilder.build();
	}

	private static List<Base64> buildX509CertChain(List<X509Certificate> certificateChain) {
		List<Base64> x5c = new ArrayList<>();
		for (X509Certificate x509Cert : certificateChain) {
			try {
				Base64 signCert = Base64.encode(x509Cert.getEncoded());
				x5c.add(signCert);
			} catch (CertificateEncodingException e) {
				// ignore this exception for each cert in the chain
				LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
						"Warning thrown when certificate not able to parse while adding to jws header.");
			}
		}
		return x5c;
	}

	private Base64URL getCertificateSHA256Thumbprint(X509Certificate x509Certificate) {
		try {
			return Base64URL.encode(DigestUtils.sha256(x509Certificate.getEncoded()));
		} catch (CertificateEncodingException e) {
			// ignore this exception.
			LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
					"Warning thrown when certificate not able to parse while adding to jws header.");
			return null;
		}
	}

	private JWSHeader.Builder addCustomHeaders(
			Map<String, String> additionalHeaders,
			JWSHeader.Builder jwsHeaderBuilder) {
		if (additionalHeaders != null) {
			for (Map.Entry<String, String> entry : additionalHeaders.entrySet()) {
				if (!JWSHeader.getRegisteredParameterNames().contains(entry.getKey())) {
					try {
						jwsHeaderBuilder = jwsHeaderBuilder.customParam(entry.getKey(), entry.getValue());
					} catch (Exception e) {
						LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
								"Warning: Failed to add custom JWS header param: " + entry.getKey(), e);
					}
				}
			}
		}
		return jwsHeaderBuilder;
	}

	private static String buildFinalKeyId(String uniqueIdentifier, boolean includeKeyId, Map<String, String> additionalHeaders, String kidPrepend) {

		String keyId = convertHexToBase64(uniqueIdentifier);
		if (!includeKeyId || keyId == null) {
			return null;
		}

		String finalPrepend = kidPrepend;
		if (additionalHeaders != null && additionalHeaders.containsKey("kid")) {
			String mapKid = additionalHeaders.get("kid");
			if (mapKid.isEmpty() || mapKid.charAt(mapKid.length() - 1) != SignatureConstant.KEY_ID_PREFIX.charAt(0)) {
				mapKid = mapKid.concat(SignatureConstant.KEY_ID_SEPARATOR);
			}
			finalPrepend = mapKid;
		}
		return finalPrepend.concat(keyId);
	}

	private JWSHeader.Builder addRegisteredJWSHeaders(Map<String, String> additionalHeaders, JWSHeader.Builder jwsHeaderBuilder) {

		if (additionalHeaders.containsKey(SignatureConstant.JWS_HEADER_TYPE_KEY)) {
			jwsHeaderBuilder.type(new JOSEObjectType(additionalHeaders.get(SignatureConstant.JWS_HEADER_TYPE_KEY)));
		}

		if (additionalHeaders.containsKey(SignatureConstant.JWS_HEADER_JWK_URL)) {
			try {
				jwsHeaderBuilder.jwkURL(new URI(additionalHeaders.get(SignatureConstant.JWS_HEADER_JWK_URL)));
			} catch (URISyntaxException e) {
				LOGGER.warn(SignatureConstant.SESSIONID, SignatureConstant.JWS_SIGN, SignatureConstant.BLANK,
						"Warning thrown when JWK URI not able to parse while adding to jws header.");
			}
		}

		if (additionalHeaders.containsKey(SignatureConstant.JWS_HEADER_CONTENT_TYPE)) {
			jwsHeaderBuilder.contentType(additionalHeaders.get(SignatureConstant.JWS_HEADER_CONTENT_TYPE));
		}

		if (additionalHeaders.containsKey(SignatureConstant.JWS_HEADER_CRTICAL_PARAM)) {
			String critValue = additionalHeaders.get(SignatureConstant.JWS_HEADER_CRTICAL_PARAM);
			Set<String> critHeaders = Arrays.stream(critValue.split(","))
					.map(String::trim)
					.collect(Collectors.toSet());
			jwsHeaderBuilder.criticalParams(critHeaders);
		}
		return jwsHeaderBuilder;
	}

    public List<X509Certificate> getX5ChainfromCoseSign1(COSESign1 coseSign1) {
        COSEProtectedHeader protectedHeader = coseSign1.getProtectedHeader();
        COSEUnprotectedHeader unprotectedHeader = coseSign1.getUnprotectedHeader();

        return protectedHeader.getX5Chain() != null ? protectedHeader.getX5Chain() : unprotectedHeader.getX5Chain();
    }

    public byte[] buildCWTClaimSet(CWTSignRequestDto requestDto) {

        CWTClaimsSetBuilder claimsSetBuilder = buildRegisteredCWTClaims(requestDto);

        if (isDataValid(requestDto.getClaim169Payload())) {
            byte[] claim169Data = decodeHex(requestDto.getClaim169Payload());
            claimsSetBuilder.put(SignatureConstant.CLAIM169_TAG, claim169Data);
        }

        if (isDataValid(requestDto.getPayload())) {
            try {
                String payload = new String(CryptoUtil.decodeURLSafeBase64(requestDto.getPayload()));
                JsonNode node = mapper.readTree(payload);

                Iterator<String> fieldNames = node.fieldNames();
                while (fieldNames.hasNext()) {
                    String keyStr = fieldNames.next();

                    // Skip registered claims
                    if (REGISTERED_CLAIMS.contains(keyStr)) {
                        continue;
                    }

                    Object key;
                    if (isNumeric(keyStr)) {
                        key = Integer.parseInt(keyStr);
                    } else {
                        key = keyStr;
                    }

                    JsonNode valueNode = node.get(keyStr);
                    Object value;

                    if (valueNode.isTextual() && isNumeric(valueNode.asText())) {
                        value = Integer.parseInt(valueNode.asText());
                    } else {
                        value = mapper.treeToValue(valueNode, Object.class);
                    }

                    claimsSetBuilder.put(key, value);
                }
            } catch (IOException e) {
                LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                        "Invalid JSON Payload Data Provided.");
                throw new RequestException(SignatureErrorCode.INVALID_JSON.getErrorCode(),
                        SignatureErrorCode.INVALID_JSON.getErrorMessage());
            }
        }

        CBORItem claimSet = claimsSetBuilder.build();
        return claimSet.encode();
    }

    private CWTClaimsSetBuilder buildRegisteredCWTClaims(CWTSignRequestDto requestDto) {
        CWTClaimsSetBuilder claimsSetBuilder = new CWTClaimsSetBuilder();

        String issuer = requestDto.getIssuer() != null ? requestDto.getIssuer() : this.signIss;
        int notBeforeIndays = requestDto.getNotBeforeDays() != null ? requestDto.getNotBeforeDays() : this.nbfInDays;
        int expireIndays = requestDto.getExpireDays() != null ? requestDto.getExpireDays() : this.expInDays;

        if (notBeforeIndays < 0 || expireIndays < 0) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_SIGN, SignatureConstant.BLANK,
                    "Not Before or Expire Date In Days cannot be negative.");
            throw new KeymanagerServiceException(SignatureErrorCode.NEGATIVE_INTEGER_ERROR.getErrorCode(),
                    SignatureErrorCode.NEGATIVE_INTEGER_ERROR.getErrorMessage().replace("{variable}", "days"));
        }

        Date issuedAt = new Date();
        Date notBefore = DateUtils.addDays(issuedAt, notBeforeIndays);
        Date expire = DateUtils.addDays(notBefore, expireIndays);
        String cwtUniqueId = UUID.randomUUID().toString();

        if (issuer != null && !issuer.isBlank()) {
            claimsSetBuilder.iss(issuer);
        }

        if (requestDto.getSubject() != null && !requestDto.getSubject().isBlank()) {
            claimsSetBuilder.sub(requestDto.getSubject());
        }

        if (requestDto.getAudience() != null && !requestDto.getAudience().isBlank()) {
            claimsSetBuilder.aud(requestDto.getAudience());
        }

        claimsSetBuilder.exp(expire);
        claimsSetBuilder.nbf(notBefore);
        claimsSetBuilder.iat(issuedAt);
        claimsSetBuilder.cti(cwtUniqueId);

        return claimsSetBuilder;
    }

    public boolean isNotBeforeDateValid(Date notBeforeDate) {
        if (notBeforeDate == null) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.BLANK, SignatureConstant.BLANK,
                    "Not Before Date is null.");
            throw new KeymanagerServiceException(KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorCode(),
                    KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorMessage());
        }
        Date currentDate = new Date();
        return !currentDate.before(notBeforeDate);
    }

    public boolean isExpireDateValid(Date expireDate) {
        if (expireDate == null) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.BLANK, SignatureConstant.BLANK,
                    "Expire Date is null.");
            throw new KeymanagerServiceException(KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorCode(),
                    KeymanagerErrorConstant.INTERNAL_SERVER_ERROR.getErrorMessage());
        }
        Date currentDate = new Date();
        return currentDate.before(expireDate);
    }

    public Map<Object, Object> constructMapfromCoseSign1Payload(COSESign1 cwtSign1) {
        try {
            byte[] cborPayloadBytes = cwtSign1.getPayload().encode();
            CBORParser cborParser = new CBORParser(cborPayloadBytes);
            Object payloadDecoder = cborParser.next();
            byte[] firstLevelBytes = (byte[]) payloadDecoder;
            CBORParser nestedParser = new CBORParser(firstLevelBytes);
            Object nestedDecoded = nestedParser.next();
            if (!(nestedDecoded instanceof Map)) {
                throw new IllegalArgumentException("Inner payload not a Map");
            }
            return (Map<Object, Object>) nestedDecoded;
        } catch (IOException e) {
            throw new RequestException(SignatureErrorCode.DATA_PARSING_ERROR.getErrorCode(),
                    SignatureErrorCode.DATA_PARSING_ERROR.getErrorMessage(), e);
        }
    }

    public static Map<String, Object> filterMapEntries(Map<String, Object> protectedHeaderMap, Map<String, Object> unprotectedHeaderMap) {
        if (protectedHeaderMap != null && !protectedHeaderMap.isEmpty()) {

            boolean includeCertChain = Boolean.TRUE.equals(protectedHeaderMap.get(SignatureConstant.INCLUDE_CERTIFICATE_CHAIN));
            boolean includeCert = Boolean.TRUE.equals(protectedHeaderMap.get(SignatureConstant.INCLUDE_CERTIFICATE));

            // If any one is true in protected, remove both keys from unprotected if present and filter out other keys with Boolean true in protected
            if (includeCertChain || includeCert) {
                unprotectedHeaderMap = unprotectedHeaderMap.entrySet().stream()
                        .filter(entry -> !SignatureConstant.INCLUDE_CERTIFICATE_CHAIN.equals(entry.getKey())
                                && !SignatureConstant.INCLUDE_CERTIFICATE.equals(entry.getKey()))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            } else {
                unprotectedHeaderMap = unprotectedHeaderMap.entrySet().stream()
                        .filter(entry -> {
                            String key = entry.getKey();

                            if (protectedHeaderMap.containsKey(key)) {
                                Object protectedVal = protectedHeaderMap.get(key);
                                // Remove only if protected header value is Boolean true
                                return !(protectedVal instanceof Boolean && (Boolean) protectedVal);
                            }
                            return true;
                        })
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            }
        }
        return unprotectedHeaderMap;
    }

    public static boolean isNumeric(String str) {
        try {
            Integer.parseInt(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public byte[] decodeHex(String hex) {
        try {
            if (!isDataValid(hex))
                return null;
            return org.bouncycastle.util.encoders.Hex.decode(hex);
        } catch (Exception e) {
            LOGGER.error(SignatureConstant.SESSIONID, SignatureConstant.COSE_VERIFY, SignatureConstant.BLANK,
                    "Error occurred parsing hex string to byte array. Check provided data is hex or not.", e);
            throw new SignatureFailureException(SignatureErrorCode.DATA_PARSING_ERROR.getErrorCode(),
                    SignatureErrorCode.DATA_PARSING_ERROR.getErrorMessage(), e);
        }
    }

    public List<? extends Certificate> getCertificateTrustChain(X509Certificate x509Certificate) {
        List<? extends Certificate> certificateChain = keymanagerUtil.getCertificateTrustPath(x509Certificate);
        if (certificateChain == null) {
            certificateChain = partnerCertificateManagerService.getCertificateTrustChain(x509Certificate, trustDomain, null);
        }

        if (certificateChain == null) {
            certificateChain = Collections.singletonList(x509Certificate);
        }

        return certificateChain;
    }
}