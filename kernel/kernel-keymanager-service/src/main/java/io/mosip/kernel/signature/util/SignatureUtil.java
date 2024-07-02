package io.mosip.kernel.signature.util;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.HMACUtils2;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.signature.constant.SignatureConstant;

/**
 * Utility class for Signature Service
 * 
 * @author Mahammed Taheer
 * @since 1.2.0-SNAPSHOT
 *
 */

public class SignatureUtil {

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
			boolean includeKeyId) {

		JWSAlgorithm jwsAlgorithm;
		switch (signAlgorithm) {
			case SignatureConstant.JWS_RS256_SIGN_ALGO_CONST:
				jwsAlgorithm = JWSAlgorithm.RS256; 
				break;
			case SignatureConstant.JWS_PS256_SIGN_ALGO_CONST:
				jwsAlgorithm = JWSAlgorithm.PS256;
				break;
			case SignatureConstant.JWS_ES256_SIGN_ALGO_CONST:
				jwsAlgorithm = JWSAlgorithm.ES256;
				break;
			case SignatureConstant.JWS_ES256K_SIGN_ALGO_CONST:
				jwsAlgorithm = JWSAlgorithm.ES256K;
				break;
			case SignatureConstant.JWS_EDDSA_SIGN_ALGO_CONST:
				jwsAlgorithm = JWSAlgorithm.EdDSA;
				break;
			default:
				jwsAlgorithm = JWSAlgorithm.PS256; 
				break;
		}
		
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
			jwsHeaderBuilder.keyID(keyId);
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

}
