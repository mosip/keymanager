/*
 * 
 * 
 * 
 * 
 */
package io.mosip.kernel.cryptomanager.util;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.constant.KeyReferenceIdConsts;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.exception.NoUniqueAliasException;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.authmanager.authadapter.model.AuthUserDetails;
import io.mosip.kernel.core.exception.ParseException;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant;
import io.mosip.kernel.cryptomanager.constant.CryptomanagerErrorCode;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.exception.CryptoManagerSerivceException;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyRequestDto;
import io.mosip.kernel.keymanagerservice.entity.KeyPolicy;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;

/**
 * Util class for this project.
 *
 * @author Urvil Joshi
 * @author Manoj SP
 * @since 1.0.0
 */
@RefreshScope
@Component
public class CryptomanagerUtils {

	private static final Logger LOGGER = KeymanagerLogger.getLogger(CryptomanagerUtils.class);

	private static ObjectMapper mapper = JsonMapper.builder().addModule(new AfterburnerModule()).build();

	/** The Constant UTC_DATETIME_PATTERN. */
	private static final String UTC_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

	/** Asymmetric Algorithm Name. */
	@Value("${mosip.kernel.keygenerator.asymmetric-algorithm-name}")
	private String asymmetricAlgorithmName;

	/** Symmetric Algorithm Name. */
	@Value("${mosip.kernel.keygenerator.symmetric-algorithm-name}")
	private String symmetricAlgorithmName;

	/** Key Splitter. */
	@Value("${mosip.kernel.data-key-splitter}")
	private String keySplitter;

	@Value("${mosip.sign-certificate-refid:SIGN}")
	private String signRefId;

	/** The sign applicationid. */
	@Value("${mosip.sign.applicationid:KERNEL}")
	private String signApplicationId;

	@Value("${mosip.kernel.keymanager.crypto.validate.keysize:true}")
	private boolean validateKeySize;

	@Value("${mosip.kernel.keymanager.jwtEncrypt.validate.json:true}")
	private boolean confValidateJson;

	/** The sign applicationid. */
	@Value("${mosip.sign.applicationid:KERNEL}")
	private String signApplicationid;

	@Value("${mosip.sign-certificate-refid:SIGN}")
	private String certificateSignRefID;

	/** The key manager. */
	@Autowired
	private KeymanagerService keyManager;

	@Autowired
	private KeymanagerUtil keymanagerUtil;

	@Autowired
	private KeymanagerDBHelper dbHelper;

	@Autowired
	private ECKeyStore keyStore;

	/** Flag to generate and store Ed25519 key in real HSM. */
	@Value("${mosip.kernel.keymanager.ed25519.hsm.support.enabled:false}")
	private boolean ed25519SupportFlag;

	/**
	 * Calls Key-Manager-Service to get public key of an application.
	 *
	 * @param cryptomanagerRequestDto            {@link CryptomanagerRequestDto} instance
	 * @return {@link Certificate} returned by Key Manager Service
	 */
	public Certificate getCertificate(CryptomanagerRequestDto cryptomanagerRequestDto) {
		String certData = getCertificateFromKeyManager(cryptomanagerRequestDto.getApplicationId(),
										cryptomanagerRequestDto.getReferenceId());

		return keymanagerUtil.convertToCertificate(certData);
	}

	/**
	 * Gets the certificate from key manager.
	 *
	 * @param appId the app id
	 * @param refId the ref id
	 * @return the certificate data from key manager
	 */
	public String getCertificateFromKeyManager(String appId, String refId) {
		return keyManager.getCertificate(appId, Optional.ofNullable(refId)).getCertificate();
	}


	/**
	 * Calls Key-Manager-Service to decrypt symmetric key.
	 *
	 * @param cryptomanagerRequestDto            {@link CryptomanagerRequestDto} instance
	 * @return Decrypted {@link SecretKey} from Key Manager Service
	 */
	public SecretKey getDecryptedSymmetricKey(CryptomanagerRequestDto cryptomanagerRequestDto) {
		byte[] symmetricKey = CryptoUtil.decodeURLSafeBase64(decryptSymmetricKeyUsingKeyManager(cryptomanagerRequestDto));
		return new SecretKeySpec(symmetricKey, 0, symmetricKey.length, symmetricAlgorithmName);
	}

	/**
	 * Decrypt symmetric key using key manager.
	 *
	 * @param cryptomanagerRequestDto the cryptomanager request dto
	 * @return the string
	 */
	@SuppressWarnings("deprecation")
	private String decryptSymmetricKeyUsingKeyManager(CryptomanagerRequestDto cryptomanagerRequestDto) {
		SymmetricKeyRequestDto symmetricKeyRequestDto = new SymmetricKeyRequestDto(
				cryptomanagerRequestDto.getApplicationId(), cryptomanagerRequestDto.getTimeStamp(),
				cryptomanagerRequestDto.getReferenceId(), cryptomanagerRequestDto.getData(), cryptomanagerRequestDto.getPrependThumbprint());
		return keyManager.decryptSymmetricKey(symmetricKeyRequestDto).getSymmetricKey();
	}

	/**
	 * Change Parameter form to trim if not null.
	 *
	 * @param parameter            parameter
	 * @return null if null;else trimmed string
	 */
	public static String nullOrTrim(String parameter) {
		return parameter == null ? null : parameter.trim();
	}

	/**
	 * Function to check is salt is valid.
	 *
	 * @param salt            salt
	 * @return true if salt is valid, else false
	 */
	public boolean isValidSalt(String salt) {
		return salt != null && !salt.trim().isEmpty();
	}

	/**
	 * Parse a date string of pattern UTC_DATETIME_PATTERN into
	 * {@link LocalDateTime}.
	 *
	 * @param dateTime of type {@link String} of pattern UTC_DATETIME_PATTERN
	 * @return a {@link LocalDateTime} of given pattern
	 */
	public LocalDateTime parseToLocalDateTime(String dateTime) {
		return LocalDateTime.parse(dateTime, DateTimeFormatter.ofPattern(UTC_DATETIME_PATTERN));
	}

	/**
	 * hex decode string to byte array
	 *
	 * @param hexData type {@link String} 
	 * @return a {@link byte[]} of given data
	 */
	public byte[] hexDecode(String hexData) {

		char[] hexDataCharArr = hexData.toCharArray();
		int dataLength = hexDataCharArr.length;

        if ((dataLength & 0x01) != 0) {
			throw new ParseException(CryptomanagerErrorCode.HEX_DATA_PARSE_EXCEPTION.getErrorCode(), 
					CryptomanagerErrorCode.HEX_DATA_PARSE_EXCEPTION.getErrorMessage());
        }

        byte[] decodedBytes = new byte[dataLength >> 1];

        for (int i = 0, j = 0; j < dataLength; i++) {
            int f = Character.digit(hexDataCharArr[j], 16) << 4;
            j++;
            f = f | Character.digit(hexDataCharArr[j], 16);
            j++;
            decodedBytes[i] = (byte) (f & 0xFF);
        }
        return decodedBytes;
	}

	public byte[] getCertificateThumbprint(Certificate cert) {
		try {
            return DigestUtils.sha256(cert.getEncoded());
		} catch (CertificateEncodingException e) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, "", 
									"Error generating certificate thumbprint.");
            throw new CryptoManagerSerivceException(CryptomanagerErrorCode.CERTIFICATE_THUMBPRINT_ERROR.getErrorCode(),
						CryptomanagerErrorCode.CERTIFICATE_THUMBPRINT_ERROR.getErrorMessage());
		}
	}

	public String getCertificateThumbprintInHex(Certificate cert) {
        return Hex.toHexString(getCertificateThumbprint(cert)).toUpperCase();
	}

	public byte[] concatCertThumbprint(byte[] certThumbprint, byte[] encryptedKey){
		byte[] finalData = new byte[CryptomanagerConstant.THUMBPRINT_LENGTH + encryptedKey.length];
		System.arraycopy(certThumbprint, 0, finalData, 0, certThumbprint.length);
		System.arraycopy(encryptedKey, 0, finalData, certThumbprint.length, encryptedKey.length);
		return finalData;
	}

	public byte[] generateRandomBytes(int size) {
		byte[] randomBytes = new byte[size];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(randomBytes);
		return randomBytes;
	}

	public byte[] concatByteArrays(byte[] array1, byte[] array2){
		byte[] finalData = new byte[array1.length + array2.length];
		System.arraycopy(array1, 0, finalData, 0, array1.length);
		System.arraycopy(array2, 0, finalData, array1.length, array2.length);
		return finalData;
	}

	public byte[] parseEncryptKeyHeader(byte[] encryptedKey){
		byte[] versionHeaderBytes = Arrays.copyOfRange(encryptedKey, 0, CryptomanagerConstant.VERSION_RSA_2048.length);
		if (!Arrays.equals(versionHeaderBytes, CryptomanagerConstant.VERSION_RSA_2048)) {
			return new byte[0];
		}
		return versionHeaderBytes;
	}

	public String getAlgorithmNameFromHeader(byte[] encryptedData) {
		int keyDelimiterIndex = 0;
		keyDelimiterIndex = CryptoUtil.getSplitterIndex(encryptedData, keyDelimiterIndex, keySplitter);
		byte[] algorithmBytes = Arrays.copyOfRange(encryptedData, 0, keyDelimiterIndex);
		String algorithmName;

		if (Arrays.equals(algorithmBytes, CryptomanagerConstant.VERSION_EC256_R1)) {
			algorithmName = CryptomanagerConstant.EC_SECP256R1;
		} else if (Arrays.equals(algorithmBytes, CryptomanagerConstant.VERSION_EC256_K1)) {
			algorithmName = CryptomanagerConstant.EC_SECP256K1;
		} else if (Arrays.equals(algorithmBytes, CryptomanagerConstant.VERSION_EC_X25519)) {
			algorithmName = CryptomanagerConstant.EC_X25519;
		} else {
			algorithmName = KeymanagerConstant.RSA;
		}
		return algorithmName;
	}

	public boolean isDataValid(String anyData) {
		return anyData != null && !anyData.trim().isEmpty();
	}

	public byte[] decodeBase64Data(String anyBase64EncodedData){

		try{
			return CryptoUtil.decodeURLSafeBase64(anyBase64EncodedData);
		} catch(IllegalArgumentException argException) {
			LOGGER.debug(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, "", 
				"Error Decoding Base64 URL Safe data, trying with Base64 normal decode.");
		}
		try {
			return CryptoUtil.decodePlainBase64(anyBase64EncodedData);
		} catch(Exception exception) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, "", 
				"Error Decoding Base64 normal decode, throwing Exception.", exception);
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.INVALID_DATA.getErrorCode(),
				CryptomanagerErrorCode.INVALID_DATA.getErrorMessage());
		}
	}

	public boolean hasKeyAccess(String applicationId) {
		if(Objects.isNull(applicationId) || applicationId.equals(KeymanagerConstant.EMPTY)) {
			return true;
		}
		
		Optional<KeyPolicy> keyPolicy = dbHelper.getKeyPolicyFromCache(applicationId);
		if(!keyPolicy.isPresent()) // not allowing decryption if not key policy found
			return false;

		String accessAllowed = keyPolicy.get().getAccessAllowed(); 
		if (Objects.isNull(accessAllowed) || accessAllowed.isEmpty()) {
			return false;
		}

		if (accessAllowed.equals(CryptomanagerConstant.NOT_APPLICABLE)) 
			return true; // allowing decryption because key policy is configured as not applicable
		
		AuthUserDetails userDetail = (AuthUserDetails) SecurityContextHolder.getContext().getAuthentication()
														.getPrincipal();
		List<String> allowedList = Stream.of(accessAllowed.split(",")).map(allowed -> allowed.trim()).collect(Collectors.toList());
		String preferredUserName = userDetail.getUsername();
		return allowedList.stream().anyMatch(preferredUserName::equalsIgnoreCase);
	}
	

	public void validateKeyIdentifierIds(String applicationId, String referenceId) {
		if(!isDataValid(referenceId) || 
			(applicationId.equalsIgnoreCase(signApplicationId) && (referenceId.equalsIgnoreCase(signRefId) ||
				referenceId.equalsIgnoreCase(KeymanagerConstant.KERNEL_IDENTIFY_CACHE)))) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, CryptomanagerConstant.ENCRYPT,
								"Not Allowed to preform encryption with Master Key.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.ENCRYPT_NOT_ALLOWED_ERROR.getErrorCode(),
						CryptomanagerErrorCode.ENCRYPT_NOT_ALLOWED_ERROR.getErrorMessage());
		}
	}

	public Certificate getCertificate(String applicationId, String referenceId) {
		String certData = getCertificateFromKeyManager(applicationId, referenceId);
		return keymanagerUtil.convertToCertificate(certData);
	}

	public void validateEncKeySize(Certificate encCert) {

		if (validateKeySize) {
			RSAPublicKey rsaPublicKey = (RSAPublicKey) encCert.getPublicKey();
			if (rsaPublicKey.getModulus().bitLength() != 2048) {
				LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT,
						"Not Allowed to preform encryption with Key size not equal to 2048 bit.");
				throw new CryptoManagerSerivceException(CryptomanagerErrorCode.ENCRYPT_NOT_ALLOWED_ERROR.getErrorCode(),
						CryptomanagerErrorCode.ENCRYPT_NOT_ALLOWED_ERROR.getErrorMessage());
			}
		}
	}

	public void validateEncryptData(String reqDataToEncrypt) {
	
		if (!isDataValid(reqDataToEncrypt)) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT,
					"Provided Data to Encrypt is invalid.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.INVALID_REQUEST.getErrorCode(),
					CryptomanagerErrorCode.INVALID_REQUEST.getErrorMessage());
		}
	}

	public void checkForValidJsonData(String decodedDataToEncrypt) {
		
		if (confValidateJson && !isJsonValid(decodedDataToEncrypt)) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT,
					"Provided Data to encrypt is not valid JSON.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.INVALID_JSON.getErrorCode(),
					CryptomanagerErrorCode.INVALID_JSON.getErrorMessage());
		}
	}

	public boolean isJsonValid(String jsonInString) {
		try {
			mapper.readTree(jsonInString);
			return true;
		} catch (IOException e) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT,
					"Provided JSON Data to Encrypt is invalid.");
		}
		return false;
	}

	public boolean isIncludeAttrsValid(Boolean includes, Boolean defaultValue) {
		if (Objects.isNull(includes)) {
			return defaultValue;
		}
		return includes;
	}

	public Certificate convertToCertificate (String certData) {
		try {
			return keymanagerUtil.convertToCertificate(certData);
		} catch (KeymanagerServiceException exp) {
			LOGGER.warn(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT,
					"Unable to parse the input certificate.");
		}
		return null;
	}

	public void validateInputData(String reqDataToDigest) {
	
		if (!isDataValid(reqDataToDigest)) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.GEN_ARGON2_HASH,
					"Provided Data to generate Hash is invalid.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.INVALID_REQUEST.getErrorCode(),
					CryptomanagerErrorCode.INVALID_REQUEST.getErrorMessage());
		}
	}

	public Object[] getEncryptedPrivateKey(String appId, Optional<String> refId) {

		LocalDateTime localDateTime = DateUtils.getUTCCurrentDateTime();
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(appId, refId.get(), localDateTime);
		KeyAlias keyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS).getFirst();
		String ksAlias = keyAlias.getAlias();

		if (!refId.isPresent() || refId.get().trim().isEmpty()) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Not valid reference Id. Getting private key from HSM.");
			KeyStore.PrivateKeyEntry masterKeyEntry = keyStore.getAsymmetricKey(ksAlias);
			PrivateKey masterPrivateKey = masterKeyEntry.getPrivateKey();
			Certificate masterCert = masterKeyEntry.getCertificate();
			return new Object[] {masterPrivateKey, masterCert};

		} else if ((appId.equalsIgnoreCase(signApplicationid) && refId.isPresent()
				&& refId.get().equals(certificateSignRefID)) ||
				(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name())) ||
				(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name())) ||
				(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.ED25519_SIGN.name())
						&& ed25519SupportFlag)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is present and it is " + refId.get() + " Signature Key ref Id. Getting private key from HSM.");
			KeyStore.PrivateKeyEntry masterKeyEntry = keyStore.getAsymmetricKey(ksAlias);
			PrivateKey masterPrivateKey = masterKeyEntry.getPrivateKey();
			Certificate masterCert = masterKeyEntry.getCertificate();
			return new Object[] {masterPrivateKey, masterCert};
		} else {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is present. Will get Certificate from DB store");

			Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> dbKeyStore = dbHelper.getKeyStoreFromDB(ksAlias);
			if (!dbKeyStore.isPresent()) {
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYFROMDB, dbKeyStore.toString(),
						"Key in DBStore does not exist for this alias. Throwing exception");
				throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
						KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
			}
			String masterKeyAlias = dbKeyStore.get().getMasterAlias();
			String privateKeyObj = dbKeyStore.get().getPrivateKey();

			if (ksAlias.equals(masterKeyAlias) || privateKeyObj.equals(KeymanagerConstant.KS_PK_NA)) {
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
						"Not Allowed to perform decryption with other domain key.");
				throw new KeymanagerServiceException(KeymanagerErrorConstant.DECRYPTION_NOT_ALLOWED.getErrorCode(),
						KeymanagerErrorConstant.DECRYPTION_NOT_ALLOWED.getErrorMessage());
			}

			KeyStore.PrivateKeyEntry masterKeyEntry = keyStore.getAsymmetricKey(dbKeyStore.get().getMasterAlias());
			PrivateKey masterPrivateKey = masterKeyEntry.getPrivateKey();
			PublicKey masterPublicKey = masterKeyEntry.getCertificate().getPublicKey();
			/**
			 * If the private key is in dbstore, then it will be first decrypted with
			 * application's master private key from softhsm's/HSM's keystore
			 */
			try {
				return getObjects(dbKeyStore, masterPrivateKey, masterPublicKey);
			} catch (Exception e) {
				// need confirm the error message and code
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
						"Error while decrypting private key from DBStore. Throwing exception", e);
				throw new KeymanagerServiceException(KeymanagerErrorConstant.NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
						KeymanagerErrorConstant.NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage());
			}
		}
    }

	public Object[] getObjects(Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> dbKeyStore, PrivateKey masterPrivateKey, PublicKey masterPublicKey) {
		byte[] decryptedPrivateKey = keymanagerUtil.decryptKey(CryptoUtil.decodeURLSafeBase64(dbKeyStore.get().getPrivateKey()),
				masterPrivateKey, masterPublicKey);

		PublicKey publicKey = keymanagerUtil.convertToCertificate(dbKeyStore.get().getCertificateData()).getPublicKey();
		String algorithmName = publicKey.getAlgorithm();
        KeyFactory keyFactory = null;
		PrivateKey privateKey = null;
        try {
            keyFactory = KeyFactory.getInstance(algorithmName);
            privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Certificate certificate = keymanagerUtil.convertToCertificate(dbKeyStore.get().getCertificateData());
		return new Object[]{privateKey, certificate};
	}

	public byte[] getHeaderByte(String ecCurveName) {
		byte[] headerBytes = new byte[0];
		if (ecCurveName.equalsIgnoreCase(CryptomanagerConstant.EC_SECP256R1)) {
			headerBytes = CryptomanagerConstant.VERSION_EC256_R1;
		} else if (ecCurveName.equalsIgnoreCase(CryptomanagerConstant.EC_SECP256K1)) {
			headerBytes = CryptomanagerConstant.VERSION_EC256_K1;
		} else if (ecCurveName.equalsIgnoreCase(CryptomanagerConstant.EC_X25519)) {
			headerBytes = CryptomanagerConstant.VERSION_EC_X25519;
		} else {
			LOGGER.error(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, CryptomanagerConstant.ENCRYPT,
					"Unsupported EC Curve Name: " + ecCurveName);
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.UNSUPPORTED_EC_CURVE.getErrorCode(),
					CryptomanagerErrorCode.UNSUPPORTED_EC_CURVE.getErrorMessage() + ecCurveName);
		}
		return headerBytes;
	}
}
