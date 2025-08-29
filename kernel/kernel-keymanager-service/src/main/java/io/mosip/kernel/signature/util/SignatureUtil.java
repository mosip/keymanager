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
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
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

import java.util.stream.Collectors;

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
					"Invalid JSON Payload Data Provided.");
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

		List<? extends Certificate> certificateChain = keymanagerUtil.getCertificateTrustPath(x509Certificate);

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
				// ignore this exception.
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
}
