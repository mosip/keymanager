
package io.mosip.kernel.cryptomanager.service.impl;

import static io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant.CACHE_INT_COUNTER;
import static io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant.DEFAULT_INCLUDES_FALSE;
import static io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant.DEFAULT_INCLUDES_TRUE;
import static java.util.Arrays.copyOfRange;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import jakarta.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;
import org.cache2k.Cache;
import org.cache2k.Cache2kBuilder;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant;
import io.mosip.kernel.cryptomanager.constant.CryptomanagerErrorCode;
import io.mosip.kernel.cryptomanager.dto.Argon2GenerateHashRequestDto;
import io.mosip.kernel.cryptomanager.dto.Argon2GenerateHashResponseDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerResponseDto;
import io.mosip.kernel.cryptomanager.dto.JWTCipherResponseDto;
import io.mosip.kernel.cryptomanager.dto.JWTDecryptRequestDto;
import io.mosip.kernel.cryptomanager.dto.JWTEncryptRequestDto;
import io.mosip.kernel.cryptomanager.exception.CryptoManagerSerivceException;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keygenerator.bouncycastle.KeyGenerator;
import io.mosip.kernel.keygenerator.bouncycastle.util.KeyGeneratorUtils;
import io.mosip.kernel.keymanagerservice.entity.KeyStore;
import io.mosip.kernel.keymanagerservice.helper.PrivateKeyDecryptorHelper;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;

/**
 * Service Implementation for {@link CryptomanagerService} interface
 * 
 * @author Urvil Joshi
 * @author Srinivasan
 *
 * @since 1.0.0
 */
@Service
public class CryptomanagerServiceImpl implements CryptomanagerService {

	private static final int GCM_NONCE_LENGTH = 12;

	private static final int PBE_SALT_LENGTH = 32;

	private static final String AES_KEY_TYPE = "AES";

	private static final int AES_KEY_SIZE = 128;

	private String AES_GCM_ALGO = "AES/GCM/NoPadding";

	private static final Logger LOGGER = KeymanagerLogger.getLogger(CryptomanagerServiceImpl.class);

	/**
	 * KeySplitter for splitting key and data
	 */
	@Value("${mosip.kernel.data-key-splitter}")
	private String keySplitter;

	/** The 1.1.3 no thumbprint support flag. */
	@Value("${mosip.kernel.keymanager.113nothumbprint.support:false}")
	private boolean noThumbprint;

	@Value("${mosip.sign-certificate-refid:SIGN}")
	private String signRefId;

	/** The sign applicationid. */
	@Value("${mosip.sign.applicationid:KERNEL}")
	private String signApplicationId;

	@Value("${mosip.keymanager.salt.params.cache.expire.inMins:30}")
    private long cacheExpireInMins;

	@Value("${mosip.keymanager.argon2.hash.generate.iterations:10}")
    private int argon2Iterations;

	@Value("${mosip.keymanager.argon2.hash.generate.memory.inKiB:65536}")
    private int argon2Memory;

	@Value("${mosip.keymanager.argon2.hash.generate.parallelism:2}")
    private int argon2Parallelism;

	private static SecureRandom secureRandom = null;

	/**
	 * {@link KeyGenerator} instance
	 */
	@Autowired
	KeyGenerator keyGenerator;

	/**
	 * {@link CryptomanagerUtils} instance
	 */
	@Autowired
	CryptomanagerUtils cryptomanagerUtil;

	/**
	 * {@link CryptoCoreSpec} instance for cryptographic functionalities.
	 */
	@Autowired
	private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

	@Autowired
	private PrivateKeyDecryptorHelper privateKeyDecryptorHelper;

	@Autowired
	KeymanagerUtil keymanagerUtil;

	private Cache<String, Object> saltGenParamsCache = null;

	@PostConstruct
    public void init() {
        // Added Cache2kBuilder in the postConstruct because expire value 
        // configured in properties are getting injected after this object creation.
        // Cache2kBuilder constructor is throwing error.
        
		saltGenParamsCache = new Cache2kBuilder<String, Object>() {}
		// added hashcode because test case execution failing with IllegalStateException: Cache already created
		.name("saltGenParamsCache-" + this.hashCode()) 
		.expireAfterWrite(cacheExpireInMins, TimeUnit.MINUTES)
		.entryCapacity(10)
		.refreshAhead(true)
		.loaderThreadCount(1)
		.loader((objectKey) -> {
			LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(),
					CryptomanagerConstant.GEN_ARGON2_HASH, "Loading Creating Cache for Object Key: " + objectKey);
			if (objectKey.equals(CryptomanagerConstant.CACHE_AES_KEY)) {
				javax.crypto.KeyGenerator keyGenerator = KeyGeneratorUtils.getKeyGenerator(AES_KEY_TYPE, 
							AES_KEY_SIZE, new SecureRandom());
				return keyGenerator.generateKey();
			} else if (objectKey.equals(CACHE_INT_COUNTER)) {
				if(secureRandom == null)
            		secureRandom = new SecureRandom();
				
				return new AtomicLong(secureRandom.nextLong());
			} 
			return null;
		})
		.build();
        
    }

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.cryptography.service.CryptographyService#encrypt(io.mosip.
	 * kernel.cryptography.dto.CryptographyRequestDto)
	 */
	@Override
	public CryptomanagerResponseDto encrypt(CryptomanagerRequestDto cryptoRequestDto) {
		LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, CryptomanagerConstant.ENCRYPT, 
						"Request for data encryption.");
		
		cryptomanagerUtil.validateKeyIdentifierIds(cryptoRequestDto.getApplicationId(), cryptoRequestDto.getReferenceId());
		SecretKey secretKey = keyGenerator.getSymmetricKey();
		final byte[] encryptedData;
		byte[] headerBytes = new byte[0];
		if (cryptomanagerUtil.isValidSalt(CryptomanagerUtils.nullOrTrim(cryptoRequestDto.getSalt()))) {
			encryptedData = cryptoCore.symmetricEncrypt(secretKey, cryptomanagerUtil.decodeBase64Data(cryptoRequestDto.getData()),
							cryptomanagerUtil.decodeBase64Data(CryptomanagerUtils.nullOrTrim(cryptoRequestDto.getSalt())),
							cryptomanagerUtil.decodeBase64Data(CryptomanagerUtils.nullOrTrim(cryptoRequestDto.getAad())));
		} else {
			byte[] aad = cryptomanagerUtil.decodeBase64Data(CryptomanagerUtils.nullOrTrim(cryptoRequestDto.getAad()));
			if (aad == null || aad.length == 0){
				encryptedData = generateAadAndEncryptData(secretKey, cryptoRequestDto.getData());
				headerBytes = CryptomanagerConstant.VERSION_RSA_2048;
			} else {
				encryptedData = cryptoCore.symmetricEncrypt(secretKey, cryptomanagerUtil.decodeBase64Data(cryptoRequestDto.getData()),
										aad);
			}
		}

		Certificate certificate = cryptomanagerUtil.getCertificate(cryptoRequestDto);
		LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, CryptomanagerConstant.ENCRYPT, 
						"Found the cerificate, proceeding with session key encryption.");
		PublicKey publicKey = certificate.getPublicKey();
		final byte[] encryptedSymmetricKey = cryptoCore.asymmetricEncrypt(publicKey, secretKey.getEncoded());
		LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, CryptomanagerConstant.ENCRYPT, 
						"Session key encryption completed.");
		//boolean prependThumbprint = cryptoRequestDto.getPrependThumbprint() == null ? false : cryptoRequestDto.getPrependThumbprint();
		CryptomanagerResponseDto cryptoResponseDto = new CryptomanagerResponseDto();
		// support of 1.1.3 no thumbprint is configured as true & encryption request with no thumbprint
		// request thumbprint flag will not be considered if support no thumbprint is set to false.
		//------------------- 
		// no thumbprint flag will not be required to consider at the time of encryption. So commented the below code.
		// from 1.2.0.1 version, support of no thumbprint flag will be removed in case of data encryption.
		/* if (noThumbprint && !prependThumbprint) {
			byte[] finalEncKeyBytes = cryptomanagerUtil.concatByteArrays(headerBytes, encryptedSymmetricKey);
			cryptoResponseDto.setData(CryptoUtil.encodeToURLSafeBase64(CryptoUtil.combineByteArray(encryptedData, finalEncKeyBytes, keySplitter)));
			return cryptoResponseDto;
		} */ 
		//---------------------
		byte[] certThumbprint = cryptomanagerUtil.getCertificateThumbprint(certificate);
		byte[] concatedData = cryptomanagerUtil.concatCertThumbprint(certThumbprint, encryptedSymmetricKey);
		byte[] finalEncKeyBytes = cryptomanagerUtil.concatByteArrays(headerBytes, concatedData);
		cryptoResponseDto.setData(CryptoUtil.encodeToURLSafeBase64(CryptoUtil.combineByteArray(encryptedData, 
							finalEncKeyBytes, keySplitter)));
		return cryptoResponseDto;
	}

	private byte[] generateAadAndEncryptData(SecretKey secretKey, String data){
		LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT, CryptomanagerConstant.ENCRYPT, 
						"Provided AAD value is null or empty byte array. So generating random 32 bytes for AAD.");
		byte[] aad = cryptomanagerUtil.generateRandomBytes(CryptomanagerConstant.GCM_AAD_LENGTH);
		byte[] nonce = copyOfRange(aad, 0, CryptomanagerConstant.GCM_NONCE_LENGTH);
		byte[] encData = cryptoCore.symmetricEncrypt(secretKey, cryptomanagerUtil.decodeBase64Data(data),
								nonce, aad);
		return cryptomanagerUtil.concatByteArrays(aad, encData);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.cryptography.service.CryptographyService#decrypt(io.mosip.
	 * kernel.cryptography.dto.CryptographyRequestDto)
	 */
	@Override
	public CryptomanagerResponseDto decrypt(CryptomanagerRequestDto cryptoRequestDto) {
		LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.DECRYPT, CryptomanagerConstant.DECRYPT, 
						"Request for data decryption.");

		boolean hasAcccess = cryptomanagerUtil.hasKeyAccess(cryptoRequestDto.getApplicationId());
		if (!hasAcccess) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.DECRYPT, CryptomanagerConstant.DECRYPT,
								"Data Decryption is not allowed for the authenticated user for the provided application id.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.DECRYPT_NOT_ALLOWED_ERROR.getErrorCode(),
						CryptomanagerErrorCode.DECRYPT_NOT_ALLOWED_ERROR.getErrorMessage());
		}
		int keyDemiliterIndex = 0;
		byte[] encryptedHybridData = cryptomanagerUtil.decodeBase64Data(cryptoRequestDto.getData());
		keyDemiliterIndex = CryptoUtil.getSplitterIndex(encryptedHybridData, keyDemiliterIndex, keySplitter);
		byte[] encryptedKey = copyOfRange(encryptedHybridData, 0, keyDemiliterIndex);
		byte[] encryptedData = copyOfRange(encryptedHybridData, keyDemiliterIndex + keySplitter.length(),
				encryptedHybridData.length);
		
		byte[] headerBytes = cryptomanagerUtil.parseEncryptKeyHeader(encryptedKey);
		cryptoRequestDto.setData(CryptoUtil.encodeToURLSafeBase64(copyOfRange(encryptedKey, headerBytes.length, encryptedKey.length)));
		SecretKey decryptedSymmetricKey = cryptomanagerUtil.getDecryptedSymmetricKey(cryptoRequestDto);
		LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.DECRYPT, CryptomanagerConstant.DECRYPT, 
						"Session Key Decryption completed.");
		final byte[] decryptedData;
		if (cryptomanagerUtil.isValidSalt(CryptomanagerUtils.nullOrTrim(cryptoRequestDto.getSalt()))) {
			decryptedData = cryptoCore.symmetricDecrypt(decryptedSymmetricKey, encryptedData,
							cryptomanagerUtil.decodeBase64Data(CryptomanagerUtils.nullOrTrim(cryptoRequestDto.getSalt())),
							cryptomanagerUtil.decodeBase64Data(CryptomanagerUtils.nullOrTrim(cryptoRequestDto.getAad())));
		} else {
			if (Arrays.equals(headerBytes, CryptomanagerConstant.VERSION_RSA_2048)) {
				decryptedData = splitAadAndDecryptData(decryptedSymmetricKey, encryptedData);
			} else {
				decryptedData = cryptoCore.symmetricDecrypt(decryptedSymmetricKey, encryptedData,
							cryptomanagerUtil.decodeBase64Data(CryptomanagerUtils.nullOrTrim(cryptoRequestDto.getAad())));
			}
		}
		LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.DECRYPT, CryptomanagerConstant.DECRYPT, 
						"Data decryption completed.");
		CryptomanagerResponseDto cryptoResponseDto = new CryptomanagerResponseDto();
		cryptoResponseDto.setData(CryptoUtil.encodeToURLSafeBase64(decryptedData));
		return cryptoResponseDto;
	}

	private byte[] splitAadAndDecryptData(SecretKey symmetricKey, byte[] encryptedData) {

		byte[] aad = copyOfRange(encryptedData, 0, CryptomanagerConstant.GCM_AAD_LENGTH);
		byte[] nonce = copyOfRange(aad, 0, CryptomanagerConstant.GCM_NONCE_LENGTH);
		byte[] finalEncData = copyOfRange(encryptedData, CryptomanagerConstant.GCM_AAD_LENGTH, encryptedData.length);
		return cryptoCore.symmetricDecrypt(symmetricKey, finalEncData, nonce, aad);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.cryptomanager.service.CryptomanagerService#encryptWithPin(io.mosip.
	 * kernel.cryptomanager.dto.CryptoWithPinRequestDto)
	 */
	@Override
	public CryptoWithPinResponseDto encryptWithPin(CryptoWithPinRequestDto requestDto) {
		LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT_PIN, CryptomanagerConstant.ENCRYPT_PIN, 
						"Request for data encryption with Pin.");

		String dataToEnc = requestDto.getData();
		String userPin = requestDto.getUserPin();

		if(!cryptomanagerUtil.isDataValid(dataToEnc) || !cryptomanagerUtil.isDataValid(userPin)) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT_PIN, CryptomanagerConstant.ENCRYPT_PIN,
								"Either Data to encrypt or user pin is blank.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.INVALID_REQUEST.getErrorCode(),
						CryptomanagerErrorCode.INVALID_REQUEST.getErrorMessage());
		}

		SecureRandom sRandom = new SecureRandom(); 
		byte[] pbeSalt = new byte[PBE_SALT_LENGTH];
		sRandom.nextBytes(pbeSalt);

		SecretKey derivedKey = getDerivedKey(userPin, pbeSalt);
		byte[] gcmNonce = new byte[GCM_NONCE_LENGTH];
		sRandom.nextBytes(gcmNonce);
		byte[] encryptedData = cryptoCore.symmetricEncrypt(derivedKey, dataToEnc.getBytes(), gcmNonce, pbeSalt);

		byte[] finalEncryptedData = new byte[encryptedData.length + PBE_SALT_LENGTH + GCM_NONCE_LENGTH];
		System.arraycopy(pbeSalt, 0, finalEncryptedData, 0, pbeSalt.length);
		System.arraycopy(gcmNonce, 0, finalEncryptedData, pbeSalt.length, gcmNonce.length);
		System.arraycopy(encryptedData, 0, finalEncryptedData, pbeSalt.length + gcmNonce.length, encryptedData.length);
		CryptoWithPinResponseDto responseDto = new CryptoWithPinResponseDto();
		responseDto.setData(CryptoUtil.encodeToURLSafeBase64(finalEncryptedData));
		return responseDto;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.cryptomanager.service.CryptomanagerService#decryptWithPin(io.mosip.
	 * kernel.cryptomanager.dto.CryptoWithPinRequestDto)
	 */
	@Override
	public CryptoWithPinResponseDto decryptWithPin(CryptoWithPinRequestDto requestDto) {
		LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT_PIN, CryptomanagerConstant.ENCRYPT_PIN, 
						"Request for data decryption with Pin.");

		String dataToDec = requestDto.getData();
		String userPin = requestDto.getUserPin();

		if(!cryptomanagerUtil.isDataValid(dataToDec) || !cryptomanagerUtil.isDataValid(userPin)) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.ENCRYPT_PIN, CryptomanagerConstant.ENCRYPT_PIN,
								"Either Data to decrypt or user pin is blank.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.INVALID_REQUEST.getErrorCode(),
						CryptomanagerErrorCode.INVALID_REQUEST.getErrorMessage());
		}

		byte[] decodedEncryptedData = CryptoUtil.decodeURLSafeBase64(dataToDec);
		byte[] pbeSalt = Arrays.copyOfRange(decodedEncryptedData, 0, PBE_SALT_LENGTH);
		byte[] gcmNonce = Arrays.copyOfRange(decodedEncryptedData, PBE_SALT_LENGTH, PBE_SALT_LENGTH + GCM_NONCE_LENGTH);
		byte[] encryptedData = Arrays.copyOfRange(decodedEncryptedData, PBE_SALT_LENGTH + GCM_NONCE_LENGTH,	decodedEncryptedData.length);

		SecretKey derivedKey = getDerivedKey(userPin, pbeSalt);
		byte[]  decryptedData = cryptoCore.symmetricDecrypt(derivedKey, encryptedData, gcmNonce, pbeSalt);
		CryptoWithPinResponseDto responseDto = new CryptoWithPinResponseDto();
		responseDto.setData(new String(decryptedData));
		return responseDto;
	}

	private SecretKey getDerivedKey(String userPin, byte[] salt) {
		String derivedKeyHex = cryptoCore.hash(userPin.getBytes(), salt);
		byte[] derivedKey = cryptomanagerUtil.hexDecode(derivedKeyHex);
		return new SecretKeySpec(derivedKey, AES_KEY_TYPE);
	}

	@Override
	public JWTCipherResponseDto jwtEncrypt(JWTEncryptRequestDto jwtEncryptRequestDto) {
		
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT, 
						"Request for JWE Encryption. Input Application Id:"  + jwtEncryptRequestDto.getApplicationId() + 
						", Reference Id: " + jwtEncryptRequestDto.getReferenceId());
		Certificate encCertificate = null;
		if (cryptomanagerUtil.isDataValid(jwtEncryptRequestDto.getX509Certificate())) {
			encCertificate = cryptomanagerUtil.convertToCertificate(jwtEncryptRequestDto.getX509Certificate());
		} 
		if (Objects.isNull(encCertificate)) {
			cryptomanagerUtil.validateKeyIdentifierIds(jwtEncryptRequestDto.getApplicationId(), jwtEncryptRequestDto.getReferenceId());
			encCertificate = cryptomanagerUtil.getCertificate(jwtEncryptRequestDto.getApplicationId(),
									 jwtEncryptRequestDto.getReferenceId());
			// getCertificate should return a valid certificate for encryption. If no certificate is available,
			// getCertificate will automatically throws an exception. So not checking for null for encCertificate. 
		}

		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT, 
						"Found the cerificate, Validating Encryption Certificate key size.");
		cryptomanagerUtil.validateEncKeySize(encCertificate);
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT, 
						"Key Size validated, validing input data.");
		
		String dataToEncrypt = jwtEncryptRequestDto.getData();
		cryptomanagerUtil.validateEncryptData(dataToEncrypt);

		String decodedDataToEncrypt = new String(CryptoUtil.decodeURLSafeBase64(dataToEncrypt));
		cryptomanagerUtil.checkForValidJsonData(decodedDataToEncrypt);
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT, 
						"Input Data validated, proceeding with JWE Encryption.");

		boolean enableDefCompression = cryptomanagerUtil.isIncludeAttrsValid(jwtEncryptRequestDto.getEnableDefCompression(), 
																		DEFAULT_INCLUDES_TRUE);
		boolean includeCertificate = cryptomanagerUtil.isIncludeAttrsValid(jwtEncryptRequestDto.getIncludeCertificate(),
																		DEFAULT_INCLUDES_FALSE);
		boolean includeCertHash = cryptomanagerUtil.isIncludeAttrsValid(jwtEncryptRequestDto.getIncludeCertHash(),
																		DEFAULT_INCLUDES_FALSE);

		String certificateUrl = cryptomanagerUtil.isDataValid(jwtEncryptRequestDto.getJwkSetUrl()) ? 
												jwtEncryptRequestDto.getJwkSetUrl(): null;

		String jweEncryptedData = jwtRsaOaep256AesGcmEncrypt(decodedDataToEncrypt, encCertificate, enableDefCompression, 
									includeCertificate, includeCertHash, certificateUrl);
		JWTCipherResponseDto jwtCipherResponseDto = new JWTCipherResponseDto();
		jwtCipherResponseDto.setData(jweEncryptedData);
		jwtCipherResponseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
		return jwtCipherResponseDto;
	}

	private String jwtRsaOaep256AesGcmEncrypt(String dataToEncrypt, Certificate certificate, boolean enableDefCompression, 
				boolean includeCertificate, boolean includeCertHash, String certificateUrl) {
		
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT, 
					"JWE Encryption Started.");
		
		JsonWebEncryption jsonWebEncrypt = new JsonWebEncryption();

		jsonWebEncrypt.setHeader(CryptomanagerConstant.JSON_CONTENT_TYPE_KEY, CryptomanagerConstant.JSON_CONTENT_TYPE_VALUE);
		jsonWebEncrypt.setHeader(CryptomanagerConstant.JSON_HEADER_TYPE_KEY, CryptomanagerConstant.JSON_CONTENT_TYPE_VALUE);
		jsonWebEncrypt.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
		jsonWebEncrypt.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
		jsonWebEncrypt.setKey(certificate.getPublicKey());
		String certThumbprint = CryptoUtil.encodeToURLSafeBase64(cryptomanagerUtil.getCertificateThumbprint(certificate));
		jsonWebEncrypt.setKeyIdHeaderValue(certThumbprint);
		byte[] nonce = cryptomanagerUtil.generateRandomBytes(CryptomanagerConstant.GCM_NONCE_LENGTH);
		jsonWebEncrypt.setIv(nonce);

		if (enableDefCompression) {
			jsonWebEncrypt.enableDefaultCompression();
		}

		if (includeCertificate) {
			jsonWebEncrypt.setCertificateChainHeaderValue(new X509Certificate[] { (X509Certificate)certificate });
		}

		if (includeCertHash) {
			jsonWebEncrypt.setX509CertSha256ThumbprintHeaderValue(certThumbprint);
		}

		if (Objects.nonNull(certificateUrl) && !certificateUrl.isEmpty()) {
			jsonWebEncrypt.setHeader(CryptomanagerConstant.JSON_HEADER_JWK_KEY, certificateUrl);
		}
		jsonWebEncrypt.setPayload(dataToEncrypt);
		try {
			String encryptedData = jsonWebEncrypt.getCompactSerialization();
			LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT, 
					"JWE Encryption Completed.");
			return encryptedData;
		} catch (JoseException e) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT, 
					"Error occurred while Json Web Encryption Data.");
					throw new CryptoManagerSerivceException(CryptomanagerErrorCode.JWE_ENCRYPTION_INTERNAL_ERROR.getErrorCode(),
					CryptomanagerErrorCode.JWE_ENCRYPTION_INTERNAL_ERROR.getErrorMessage(), e);
		}
	}

	@Override
	public JWTCipherResponseDto jwtDecrypt(JWTDecryptRequestDto jwtDecryptRequestDto) {

		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_DECRYPT, 
						"Request for JWE Decryption. Input Application Id:"  + jwtDecryptRequestDto.getApplicationId() + 
						", Reference Id: " + jwtDecryptRequestDto.getReferenceId());
		
		cryptomanagerUtil.validateKeyIdentifierIds(jwtDecryptRequestDto.getApplicationId(), jwtDecryptRequestDto.getReferenceId());
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_DECRYPT, 
						"Application Id and Reference Id validation completed, Validating Input Enc Data.");
		
		String dataToDecrypt = jwtDecryptRequestDto.getEncData();
		if (!cryptomanagerUtil.isDataValid(dataToDecrypt)) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_DECRYPT,
					"Provided Data to Decrypt is invalid.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.INVALID_REQUEST.getErrorCode(),
					CryptomanagerErrorCode.INVALID_REQUEST.getErrorMessage());
		}

		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_DECRYPT, 
						"Input Enc Data validated, proceeding with JWE Decryption.");

		JsonWebEncryption jsonWebDecrypt = new JsonWebEncryption();
		setEncryptedData(jsonWebDecrypt, dataToDecrypt);
		String keyId = jsonWebDecrypt.getKeyIdHeaderValue();
		String certThumbprintHex = Hex.toHexString(CryptoUtil.decodeURLSafeBase64(keyId)).toUpperCase();
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_DECRYPT, 
						"Fetched KeyId(CertificateThumbprint) from JWT Header, TP Value: " + certThumbprintHex);	
		String applicationId = jwtDecryptRequestDto.getApplicationId();
		String referenceId = jwtDecryptRequestDto.getReferenceId();
		KeyStore dbKeyStoreObj = privateKeyDecryptorHelper.getDBKeyStoreData(certThumbprintHex, applicationId, referenceId);

		Object[] keys = privateKeyDecryptorHelper.getKeyObjects(dbKeyStoreObj, false);
		PrivateKey privateKey = (PrivateKey) keys[0];

		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_DECRYPT, 
						"Private Key Retrival completed, processing with JWE Decryption.");
		String decryptedData = getDecryptedData(jsonWebDecrypt, privateKey);

		JWTCipherResponseDto jwtCipherResponseDto = new JWTCipherResponseDto();
		jwtCipherResponseDto.setData(CryptoUtil.encodeToURLSafeBase64(decryptedData.getBytes()));
		jwtCipherResponseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
		return jwtCipherResponseDto;
	}

	private void setEncryptedData(JsonWebEncryption jsonWebDecrypt, String dataToDecrypt) {
		try {
			LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_DECRYPT, 
					"Setting Encrypted Data for decryption.");
			jsonWebDecrypt.setCompactSerialization(dataToDecrypt);			
		} catch (JoseException e) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT, 
					"Error occurred while Json Web Decryption Data.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.JWE_DECRYPTION_INTERNAL_ERROR.getErrorCode(),
					CryptomanagerErrorCode.JWE_DECRYPTION_INTERNAL_ERROR.getErrorMessage(), e);
		}
	}

	private String getDecryptedData(JsonWebEncryption jsonWebDecrypt, PrivateKey privateKey) {
		try {
			jsonWebDecrypt.setKey(privateKey);
			LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_DECRYPT, 
					"Decrypting input encrypted Data.");
			String decryptedData = jsonWebDecrypt.getPlaintextString();
			keymanagerUtil.destoryKey(privateKey);
			return decryptedData;
		} catch (JoseException e) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.JWT_ENCRYPT, 
					"Error occurred while Json Web Decryption Data.");
			throw new CryptoManagerSerivceException(CryptomanagerErrorCode.JWE_DECRYPTION_INTERNAL_ERROR.getErrorCode(),
					CryptomanagerErrorCode.JWE_DECRYPTION_INTERNAL_ERROR.getErrorMessage(), e);
		}
	}

	@Override
	public Argon2GenerateHashResponseDto generateArgon2Hash(Argon2GenerateHashRequestDto argon2GenHashRequestDto) {
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.GEN_ARGON2_HASH, 
						"Request for Argon2 Hash Geneation.");
		
		cryptomanagerUtil.validateInputData(argon2GenHashRequestDto.getInputData());

		String inputData = argon2GenHashRequestDto.getInputData();
		String saltData = argon2GenHashRequestDto.getSalt();
		byte[] saltBytes = null;
		if (!cryptomanagerUtil.isDataValid(saltData)) {
			SecretKey aesKey = (SecretKey) saltGenParamsCache.get(CryptomanagerConstant.CACHE_AES_KEY);
			AtomicLong intCounter = (AtomicLong) saltGenParamsCache.get(CryptomanagerConstant.CACHE_INT_COUNTER);
			long saltInput = intCounter.getAndIncrement();
			saltGenParamsCache.put(CryptomanagerConstant.CACHE_INT_COUNTER, intCounter);
			saltBytes = getSaltBytes(getLongBytes(saltInput), aesKey);
			saltData = CryptoUtil.encodeToURLSafeBase64(saltBytes);
		} else {
			saltBytes = CryptoUtil.decodeURLSafeBase64(saltData);
		}
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.GEN_ARGON2_HASH, 
						"InputData is valid and salt bytes generated.");
		Argon2Advanced  argon2Advanced = Argon2Factory.createAdvanced(Argon2Types.ARGON2id);
		char[] inputDataCharArr = inputData.toCharArray();
		byte[] argon2Hash = argon2Advanced.rawHash(argon2Iterations, argon2Memory, argon2Parallelism, inputDataCharArr, saltBytes);
		String argon2HashStr = CryptoUtil.encodeToURLSafeBase64(argon2Hash);
		inputDataCharArr = null;
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.GEN_ARGON2_HASH, 
						"Argon to hash generation done.");
		
		Argon2GenerateHashResponseDto hashResponseDto = new Argon2GenerateHashResponseDto();
		hashResponseDto.setHashValue(argon2HashStr);
		hashResponseDto.setSalt(saltData);
		return hashResponseDto;
	}

	private byte[] getLongBytes(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();
	}

	private byte[] getSaltBytes(byte[] randomBytes, SecretKey aesKey) {
		try {
			Cipher cipher = Cipher.getInstance(AES_GCM_ALGO);
			cipher.init(Cipher.ENCRYPT_MODE, aesKey);
			return cipher.doFinal(randomBytes, 0, randomBytes.length);
		} catch(NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException
			| IllegalBlockSizeException | BadPaddingException | IllegalArgumentException e) {
			LOGGER.error(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), 
						CryptomanagerConstant.GEN_ARGON2_HASH,	"Error generation of random salt.", e);
		}
		LOGGER.info(CryptomanagerConstant.SESSIONID, this.getClass().getSimpleName(), CryptomanagerConstant.GEN_ARGON2_HASH, 
						"Generating Random Salt using Secure Random because encrypted random bytes failed.");
		if(secureRandom == null)
            secureRandom = new SecureRandom();

        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return bytes;
	}


}
