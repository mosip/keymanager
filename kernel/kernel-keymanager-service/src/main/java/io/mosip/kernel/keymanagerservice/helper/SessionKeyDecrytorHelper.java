package io.mosip.kernel.keymanagerservice.helper;

import java.security.KeyFactory;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import io.mosip.kernel.core.crypto.exception.InvalidKeyException;
import io.mosip.kernel.core.crypto.exception.NullDataException;
import io.mosip.kernel.core.crypto.exception.NullKeyException;
import io.mosip.kernel.core.crypto.exception.NullMethodException;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyRequestDto;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyResponseDto;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.exception.CryptoException;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.exception.NoUniqueAliasException;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;


/**
 * Session key decryption Helper class for Keymanager
 * 
 * @author Mahammed Taheer
 * @since 1.2.0
 *
 */
@Component
public class SessionKeyDecrytorHelper {
    
	private static final Logger LOGGER = KeymanagerLogger.getLogger(SessionKeyDecrytorHelper.class);

	/**
	 * {@link CryptoCoreSpec} instance for cryptographic functionalities.
	 */
	@Autowired
	private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

	/**
	 * Utility to generate Metadata
	 */
	@Autowired
	KeymanagerUtil keymanagerUtil;

	/**
	 * KeymanagerDBHelper instance to handle all DB operations
	 */
	@Autowired
	private KeymanagerDBHelper dbHelper;

	/**
	 * {@link CryptomanagerUtils} instance
	 */
	@Autowired
	CryptomanagerUtils cryptomanagerUtil;

	/**
	 * Keystore instance to handles and store cryptographic keys.
	 */
	@Autowired
	private ECKeyStore keyStore;

	@Autowired
	private PrivateKeyDecryptorHelper privateKeyDecryptorHelper;

    public SymmetricKeyResponseDto decryptSessionKey(SymmetricKeyRequestDto symmetricKeyRequestDto) {
		LocalDateTime localDateTimeStamp = DateUtils.getUTCCurrentDateTime();
		String applicationId = symmetricKeyRequestDto.getApplicationId();
		String referenceId = symmetricKeyRequestDto.getReferenceId();
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SYMMETRICKEYREQUEST,
				symmetricKeyRequestDto.getApplicationId(), "Request Application Id: " + applicationId);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SYMMETRICKEYREQUEST,
				symmetricKeyRequestDto.getApplicationId(), "Request Reference Id: " + referenceId);

		Boolean reqPrependThumbprint = symmetricKeyRequestDto.getPrependThumbprint(); 
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SYMMETRICKEYREQUEST,
				symmetricKeyRequestDto.getApplicationId(), "prependThumbprint Value(Request): " + reqPrependThumbprint);
		boolean prependThumbprint = reqPrependThumbprint == null? false : symmetricKeyRequestDto.getPrependThumbprint();
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SYMMETRICKEYREQUEST,
				symmetricKeyRequestDto.getApplicationId(), "prependThumbprint Value: " + prependThumbprint);
		/*LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SYMMETRICKEYREQUEST,
				symmetricKeyRequestDto.getApplicationId(), "1.1.3 Thumbprint support property flag: " + noThumbprint); */
				
		byte[] encryptedData = CryptoUtil.decodeURLSafeBase64(symmetricKeyRequestDto.getEncryptedSymmetricKey());
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.SYMMETRICKEYREQUEST,
				symmetricKeyRequestDto.getApplicationId(), "Encrypted Data length: " + encryptedData.length);
		if (encryptedData.length != (CryptomanagerConstant.ENCRYPTED_SESSION_KEY_LENGTH 
													+ CryptomanagerConstant.THUMBPRINT_LENGTH)) {
			return decryptSymmetricKeyNoKeyIdentifier(applicationId, referenceId, encryptedData, localDateTimeStamp);
		}
		return decryptSymmetricKeyWithKeyIdentifier(applicationId, referenceId, encryptedData, localDateTimeStamp);
    }

    /*
	 * To Support only with thumbprint.
	 * 
	 * @see
	 * io.mosip.kernel.keymanager.service.KeymanagerService#decryptSymmetricKey(java
	 * .lang.String, java.time.LocalDateTime, java.util.Optional, byte[])
	 */
	private SymmetricKeyResponseDto decryptSymmetricKeyWithKeyIdentifier(String applicationId, String referenceId, 
							byte[] encryptedData, LocalDateTime localDateTimeStamp) {
		
		
		byte[] certThumbprint = Arrays.copyOfRange(encryptedData, 0, CryptomanagerConstant.THUMBPRINT_LENGTH);
		byte[] encryptedSymmetricKey = Arrays.copyOfRange(encryptedData, CryptomanagerConstant.THUMBPRINT_LENGTH, 
									encryptedData.length);
		String certThumbprintHex = Hex.toHexString(certThumbprint).toUpperCase();
		/* io.mosip.kernel.keymanagerservice.entity.KeyStore dbKeyStore = cacheKeyStore.getOrDefault(certThumbprintHex, null);

		String appIdRefIdKey = applicationId + KeymanagerConstant.HYPHEN + referenceId;
		String compMasterKeyRefId = applicationId + KeymanagerConstant.HYPHEN + KeymanagerConstant.COMPONENT_MASTER_KEY_DUMMY_REF; 
		if(Objects.isNull(dbKeyStore)) {
			dbKeyStore = dbHelper.getKeyAlias(certThumbprintHex, appIdRefIdKey, applicationId, referenceId);
			cacheKeyStore.put(certThumbprintHex, dbKeyStore);
			// Added condition to handle issue related to decryption error with Master key.
			if (Objects.isNull(dbKeyStore.getPrivateKey())) {
				cacheReferenceIds.put(certThumbprintHex, compMasterKeyRefId);
			} else {
				cacheReferenceIds.put(certThumbprintHex, appIdRefIdKey);
			}
		}

		String cachedRefId = cacheReferenceIds.getOrDefault(certThumbprintHex, null);
		if (!appIdRefIdKey.equals(cachedRefId) && !compMasterKeyRefId.equals(cachedRefId)){
            LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                "Application Id & Reference ID not matching with the input thumbprint value(decrypt).");
            throw new KeymanagerServiceException(KeymanagerErrorConstant.APP_ID_REFERENCE_ID_NOT_MATCHING.getErrorCode(),
                KeymanagerErrorConstant.APP_ID_REFERENCE_ID_NOT_MATCHING.getErrorMessage());
        } */

		io.mosip.kernel.keymanagerservice.entity.KeyStore dbKeyStore = privateKeyDecryptorHelper.getDBKeyStoreData(certThumbprintHex, 
																		applicationId, referenceId);
		SymmetricKeyResponseDto keyResponseDto = new SymmetricKeyResponseDto();
		byte[] decryptedSymmetricKey = decryptSessionKeyWithCertificateThumbprint(dbKeyStore, encryptedSymmetricKey, referenceId);
		keyResponseDto.setSymmetricKey(CryptoUtil.encodeToURLSafeBase64(decryptedSymmetricKey));
		return keyResponseDto;

	}

	private byte[] decryptSessionKeyWithCertificateThumbprint(io.mosip.kernel.keymanagerservice.entity.KeyStore dbKeyStore, 
			byte[] encryptedSymmetricKey, String referenceId) {
		
		Object[] keys = privateKeyDecryptorHelper.getKeyObjects(dbKeyStore, true);
		PrivateKey privateKey = (PrivateKey) keys[0];
		PublicKey publicKey = ((Certificate) keys[1]).getPublicKey();
		try {
			byte[] decryptedSessionKey = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encryptedSymmetricKey);
			if(keymanagerUtil.isValidReferenceId(referenceId))
				keymanagerUtil.destoryKey(privateKey);
			return decryptedSessionKey;
		} catch(InvalidKeyException keyExp) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, KeymanagerConstant.REFERENCEID,
						"Error occurred because of mismatch with keys. Try with keys for decryption.");
			throw new CryptoException(KeymanagerErrorConstant.SYMMETRIC_KEY_DECRYPTION_FAILED.getErrorCode(),
						KeymanagerErrorConstant.SYMMETRIC_KEY_DECRYPTION_FAILED.getErrorMessage() + keyExp.getMessage(), keyExp);
		}
	}

	/* private Object[] getKeyObjects(io.mosip.kernel.keymanagerservice.entity.KeyStore dbKeyStore) {
		
		String ksAlias = dbKeyStore.getAlias();

		String privateKeyObj = dbKeyStore.getPrivateKey();
		if (Objects.isNull(privateKeyObj)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Private not found in key store. Getting private key from HSM.");
			PrivateKeyEntry masterKeyEntry = keyStore.getAsymmetricKey(ksAlias);
			PrivateKey masterPrivateKey = masterKeyEntry.getPrivateKey();
			Certificate masterCert = masterKeyEntry.getCertificate();
			return new Object[] {masterPrivateKey, masterCert};
		}
			
		String masterKeyAlias = dbKeyStore.getMasterAlias();
		
		if (ksAlias.equals(masterKeyAlias) || privateKeyObj.equals(KeymanagerConstant.KS_PK_NA)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Not Allowed to perform decryption with other domain key.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.DECRYPTION_NOT_ALLOWED.getErrorCode(),
					KeymanagerErrorConstant.DECRYPTION_NOT_ALLOWED.getErrorMessage());
		}
		
		PrivateKeyEntry masterKeyEntry = keyStore.getAsymmetricKey(dbKeyStore.getMasterAlias());
		PrivateKey masterPrivateKey = masterKeyEntry.getPrivateKey();
		PublicKey masterPublicKey = masterKeyEntry.getCertificate().getPublicKey();
		try {
			byte[] decryptedPrivateKey = keymanagerUtil.decryptKey(CryptoUtil.decodeURLSafeBase64(dbKeyStore.getPrivateKey()), 
												masterPrivateKey, masterPublicKey);
			KeyFactory keyFactory = KeyFactory.getInstance(KeymanagerConstant.RSA);
			PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKey));
			Certificate certificate = keymanagerUtil.convertToCertificate(dbKeyStore.getCertificateData());
			return new Object[] {privateKey, certificate};
		} catch (InvalidDataException | InvalidKeyException | NullDataException | NullKeyException
				| NullMethodException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new CryptoException(KeymanagerErrorConstant.CRYPTO_EXCEPTION.getErrorCode(),
					KeymanagerErrorConstant.CRYPTO_EXCEPTION.getErrorMessage() + e.getMessage(), e);
		}
	} */

	/* private byte[] decryptSessionKeyWithKeyIdentifier(String applicationId, String referenceId, LocalDateTime localDateTimeStamp, 
						byte[] encryptedSymmetricKey, byte[] certThumbprint) {
		
		Map<String, List<KeyAlias>> keyAliasMap;
		if (!keymanagerUtil.isValidReferenceId(referenceId)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
			KeymanagerConstant.NOT_A_VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITHOUT_REFERENCE_ID);
			keyAliasMap = dbHelper.getKeyAliases(applicationId, KeymanagerConstant.EMPTY, localDateTimeStamp);
		} else {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
			KeymanagerConstant.VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITH_REFERENCE_ID);
			keyAliasMap = dbHelper.getKeyAliases(applicationId, referenceId, localDateTimeStamp);
		}

		List<KeyAlias> keyAlias = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
		List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
		if (keyAlias.isEmpty()) {
			// Check Master Key exists to perform for decryption.
			keyAliasMap = dbHelper.getKeyAliases(applicationId, KeymanagerConstant.EMPTY, localDateTimeStamp);
			keyAlias = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
		 	currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
			if (keyAlias.isEmpty()) { 
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS,
						String.valueOf(keyAlias.size()), "KeyAlias is empty(with Key Identifier) Throwing exception");
				throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
						KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
			}
			// resetting the reference id to blank because base key is not generated but data encrypted with master key.
			// And to avoid no key alias found exception in getKeyObjects method.
			if(keymanagerUtil.isValidReferenceId(referenceId))
				referenceId = KeymanagerConstant.EMPTY;
		}

		Object[] keys = getKeyObjects(keyAlias, currentKeyAlias, localDateTimeStamp, referenceId, 
									certThumbprint, applicationId);
		PrivateKey privateKey = (PrivateKey) keys[0];
		PublicKey publicKey = ((Certificate) keys[1]).getPublicKey();
		try {
			byte[] decryptedSessionKey = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encryptedSymmetricKey);
			if(keymanagerUtil.isValidReferenceId(referenceId))
				keymanagerUtil.destoryKey(privateKey);
			return decryptedSessionKey;
		} catch(InvalidKeyException keyExp) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, KeymanagerConstant.REFERENCEID,
						"Error occurred because of mismatch with keys. Try with keys for decryption.");
			throw new CryptoException(KeymanagerErrorConstant.SYMMETRIC_KEY_DECRYPTION_FAILED.getErrorCode(),
						KeymanagerErrorConstant.SYMMETRIC_KEY_DECRYPTION_FAILED.getErrorMessage() + keyExp.getMessage(), keyExp);
		}
	} */

	private Object[] getKeyObjects(List<KeyAlias> keyAlias, List<KeyAlias>  currentKeyAlias, LocalDateTime timeStamp, 
				String referenceId,  byte[] reqCertThumbprint, String applicationId) {
		if (currentKeyAlias.size() == 1) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS, currentKeyAlias.get(0).getAlias(),
							"CurrentKeyAlias size is one. Will decrypt symmetric key with this alias after thumbprint matches.");
			KeyAlias fetchedKeyAlias = currentKeyAlias.get(0);
			Object[] keys = getPrivateKey(referenceId, fetchedKeyAlias);
			if (reqCertThumbprint == null){
				return keys;
			}
			Certificate certificate = (Certificate) keys[1];
			byte[] certThumbprint = cryptomanagerUtil.getCertificateThumbprint(certificate);
			if (Arrays.equals(reqCertThumbprint, certThumbprint))
				return keys;
		}
		
		if ((keyAlias.isEmpty() || currentKeyAlias.size() > 1) && reqCertThumbprint == null) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()), "KeyAlias is empty or current key alias is not unique & certificate thumbprint is null. " +
															"Throwing exception");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		}

		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS, "",
							"CurrentKeyAlias size is zero or thumbprint not matched now checking " +
							"other expired key aliases to compare thumbprint.");
		for (KeyAlias otherAlias : keyAlias) {
			Object[] keys = getPrivateKey(referenceId, otherAlias);
			Certificate certificate = (Certificate) keys[1];
			byte[] certThumbprint = cryptomanagerUtil.getCertificateThumbprint(certificate);
			if (Arrays.equals(reqCertThumbprint, certThumbprint))
				return keys;
		}
		// Check whether Thumbprint is matching with the master key(s).
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS, "",
							"Base key certificate thumbprint did not matched with thumbprint in encrypted data, " +
							"Checking thumbprint match with master key.");
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(applicationId, KeymanagerConstant.EMPTY, timeStamp);
		List<KeyAlias> masterKeyAlias = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
		for (KeyAlias masterAlias : masterKeyAlias) {
			Object[] keys = getPrivateKey(KeymanagerConstant.EMPTY, masterAlias);
			Certificate certificate = (Certificate) keys[1];
			byte[] certThumbprint = cryptomanagerUtil.getCertificateThumbprint(certificate);
			if (Arrays.equals(reqCertThumbprint, certThumbprint))
				return keys;
		}

		LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS, "",
					 "No Key Alias for the thumbprint provided (After comparing all thumbprints), Throwing exception");
		throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
				KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
	}

	/**
	 * Function to get Private Key which will be used to decrypt symmetric key.
	 * 
	 * @param referenceId     referenceId
	 * @param fetchedKeyAlias fetchedKeyAlias
	 * @return Private key
	 */
	private Object[] getPrivateKey(String referenceId, KeyAlias fetchedKeyAlias) {
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.REFERENCEID, referenceId,
				KeymanagerConstant.GETPRIVATEKEY);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.FETCHEDKEYALIAS, fetchedKeyAlias.getAlias(),
				KeymanagerConstant.GETPRIVATEKEY);

		if (!keymanagerUtil.isValidReferenceId(referenceId)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Not valid reference Id. Getting private key from HSM.");
			PrivateKeyEntry masterKeyEntry = keyStore.getAsymmetricKey(fetchedKeyAlias.getAlias());
			PrivateKey masterPrivateKey = masterKeyEntry.getPrivateKey();
			Certificate masterCert = masterKeyEntry.getCertificate();
			return new Object[] {masterPrivateKey, masterCert};
		} else {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Valid reference Id. Getting private key from DB Store");
			String ksAlias = fetchedKeyAlias.getAlias();
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
			
			PrivateKeyEntry masterKeyEntry = keyStore.getAsymmetricKey(dbKeyStore.get().getMasterAlias());
			PrivateKey masterPrivateKey = masterKeyEntry.getPrivateKey();
			PublicKey masterPublicKey = masterKeyEntry.getCertificate().getPublicKey();
			/**
			 * If the private key is in dbstore, then it will be first decrypted with
			 * application's master private key from softhsm's/HSM's keystore
			 */
			try {
				byte[] decryptedPrivateKey = keymanagerUtil.decryptKey(CryptoUtil.decodeURLSafeBase64(dbKeyStore.get().getPrivateKey()), 
													masterPrivateKey, masterPublicKey);
				KeyFactory keyFactory = KeyFactory.getInstance(KeymanagerConstant.RSA);
				PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKey));
				Certificate certificate = keymanagerUtil.convertToCertificate(dbKeyStore.get().getCertificateData());
				return new Object[] {privateKey, certificate};
			} catch (InvalidDataException | InvalidKeyException | NullDataException | NullKeyException
					| NullMethodException | InvalidKeySpecException | NoSuchAlgorithmException e) {
				throw new CryptoException(KeymanagerErrorConstant.CRYPTO_EXCEPTION.getErrorCode(),
						KeymanagerErrorConstant.CRYPTO_EXCEPTION.getErrorMessage() + e.getMessage(), e);
			}
		}
	}

	/*
	 * To Support 1.1.3 decryption & after thumbprint addition.
	 * 
	 * @see
	 * io.mosip.kernel.keymanager.service.KeymanagerService#decryptSymmetricKey(java
	 * .lang.String, java.time.LocalDateTime, java.util.Optional, byte[])
	 */
	private SymmetricKeyResponseDto decryptSymmetricKeyNoKeyIdentifier(String applicationId, String referenceId,
			byte[] encryptedData, LocalDateTime localDateTimeStamp) {
		
		byte[] certThumbprint = null;
		byte[] encryptedSymmetricKey = null;
		boolean prependThumbprint = false;
		// Thumbprint flag is false in both encryption & decryption, then consider the latest 
		// current key for decryption instead of taking the first generated key.
		// to Support packet encryption done in 1.1.3(flag: flase) and packet decryption is performed above 1.1.4 (flag: true).
		/* if(encryptedData.length == (CryptomanagerConstant.ENCRYPTED_SESSION_KEY_LENGTH 
											+ CryptomanagerConstant.THUMBPRINT_LENGTH)) {
			return decryptSymmetricKeyWithKeyIdentifier(applicationId, referenceId, encryptedData, localDateTimeStamp);
		} */
		encryptedSymmetricKey = encryptedData;
		SymmetricKeyResponseDto keyResponseDto = new SymmetricKeyResponseDto();
		byte[] decryptedSymmetricKey = decryptSessionKeyNoKeyIdentifier(applicationId, referenceId, localDateTimeStamp, 
							encryptedSymmetricKey, certThumbprint, prependThumbprint);
		keyResponseDto.setSymmetricKey(CryptoUtil.encodeToURLSafeBase64(decryptedSymmetricKey));
		return keyResponseDto;

	}

	@SuppressWarnings("java:S2259") // added suppress for sonarcloud, below logic will throw either one exception if not able to decrypt. 
	private byte[] decryptSessionKeyNoKeyIdentifier(String applicationId, String referenceId, LocalDateTime localDateTimeStamp, 
						byte[] encryptedSymmetricKey, byte[] certThumbprint, boolean packetTPFlag) {
		
		Map<String, List<KeyAlias>> keyAliasMap;
		if (!keymanagerUtil.isValidReferenceId(referenceId)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
				KeymanagerConstant.NOT_A_VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITHOUT_REFERENCE_ID);
			keyAliasMap = dbHelper.getKeyAliases(applicationId, KeymanagerConstant.EMPTY, localDateTimeStamp);
		} else {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
				KeymanagerConstant.VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITH_REFERENCE_ID);
			keyAliasMap = dbHelper.getKeyAliases(applicationId, referenceId, localDateTimeStamp);
		}

		List<KeyAlias> keyAlias = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
		List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
		InvalidKeyException keyException = null;
		InvalidDataException dataException = null;
		Object[] keys = getPrivateKeyNoKeyIdentifier(keyAlias, currentKeyAlias, localDateTimeStamp, referenceId, 
								certThumbprint, packetTPFlag, applicationId);
		PrivateKey privateKey = (PrivateKey) keys[0];
		PublicKey publicKey = ((Certificate) keys[1]).getPublicKey();
		try {
			byte[] decryptedSessionKey = cryptoCore.asymmetricDecrypt(privateKey, publicKey, encryptedSymmetricKey);
			return decryptedSessionKey;
		} catch(InvalidKeyException keyExp) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, KeymanagerConstant.REFERENCEID,
						"Error occurred because of mismatch with keys. Try with keys for decryption.");
			keyException = keyExp;
		} catch (InvalidDataException dataExp) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, KeymanagerConstant.REFERENCEID,
					"Error occurred because of mismatch with keys. Try with other current key for decryption.");
			dataException = dataExp;
		}
		// Taking the all DB keys for decryption to handle scenario - 
		// Current key got rotated and there are more than 1 keys in DB. Packet encrypted with thumbprint flag as false 
		// and used the latest key for encryption. Finally trying with all keys for decryption. 
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, KeymanagerConstant.REFERENCEID, 
									"Unable to decrypt session key with all the other validations, " +
									"trying the keys available for provided AppId & RefId.");
		try {
			return decryptWithKeyAlias(keyAlias, referenceId, encryptedSymmetricKey);
		} catch (InvalidKeyException keyExp) {
			keyException = keyExp;
		} catch (InvalidDataException dataExp) {
			dataException = dataExp;
		}
		
		// Check whether data is decrypting with the master key(s).
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, KeymanagerConstant.REFERENCEID, 
									"Unable to decrypt session key with all the base keys, " +
									"trying with master keys available for provided AppId.");
		Map<String, List<KeyAlias>> masterKeyAliasMap = dbHelper.getKeyAliases(applicationId, KeymanagerConstant.EMPTY, localDateTimeStamp);
		List<KeyAlias> masterKeyAlias = masterKeyAliasMap.get(KeymanagerConstant.KEYALIAS);
		try {
			return decryptWithKeyAlias(masterKeyAlias, KeymanagerConstant.EMPTY, encryptedSymmetricKey);
		} catch (InvalidKeyException keyExp) {
			keyException = keyExp;
		} catch (InvalidDataException dataExp) {
			dataException = dataExp;
		}

		if(keyException == null) 
			throw dataException; 
			 
		throw keyException;
	}

	/**
	 * get private key base
	 * 
	 */
	private Object[] getPrivateKeyNoKeyIdentifier(List<KeyAlias> keyAlias, List<KeyAlias> currentKeyAlias, 
							LocalDateTime timeStamp, String referenceId,  
							byte[] reqCertThumbprint, boolean packetTPFlag, String applicationId) {
		List<KeyAlias> keyAliasCp = keyAlias;
		List<KeyAlias> currentKeyAliasCp = currentKeyAlias;
		if (keyAlias.isEmpty()) {
			// Check Master Key exists to perform for decryption.
			Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(applicationId, KeymanagerConstant.EMPTY, timeStamp);
			keyAliasCp = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
		 	currentKeyAliasCp = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
			if (keyAliasCp.isEmpty()) { 
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS,
					String.valueOf(keyAlias.size()), "KeyAlias is empty(no Key Identifier) Throwing exception");
				throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
			}
			// resetting the reference id to blank because base key is not generated but data encrypted with master key.
			// And to avoid no key alias found exception in getKeyObjects method.
			if(keymanagerUtil.isValidReferenceId(referenceId))
				referenceId = KeymanagerConstant.EMPTY;
		}

		// to Support packet encryption done in 1.1.3(flag: flase) and packet decryption is performed in 1.1.4 (flag: true).
		// Considering always the first key generated for the application id & reference id
		if (Objects.isNull(reqCertThumbprint) && !packetTPFlag) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS, keyAliasCp.get(0).getAlias(),
							"Thumbprint is value is null and packet Thumbprint Flag is false.");
			KeyAlias fetchedKeyAlias = keyAliasCp.get(0);
			return getPrivateKey(referenceId, fetchedKeyAlias);
		}
		return getKeyObjects(keyAliasCp, currentKeyAliasCp, timeStamp, referenceId, reqCertThumbprint, applicationId);
	}

	@SuppressWarnings("java:S2259")  // added suppress for sonarcloud, below logic will throw either one exception if not able to decrypt.
	private byte[] decryptWithKeyAlias(List<KeyAlias> keyAlias, String referenceId, byte[]  encryptedSymmetricKey) {
		InvalidKeyException keyException = null;
		InvalidDataException dataException = null;
		for (KeyAlias alias : keyAlias) {
			Object[] dbKeys = getPrivateKey(referenceId, alias);
			PrivateKey dbPrivateKey = (PrivateKey) dbKeys[0];
			PublicKey dbPublicKey = ((Certificate) dbKeys[1]).getPublicKey();
			try {
				byte[] decryptedSessionKey = cryptoCore.asymmetricDecrypt(dbPrivateKey, dbPublicKey, encryptedSymmetricKey);
				if(keymanagerUtil.isValidReferenceId(referenceId))
					keymanagerUtil.destoryKey(dbPrivateKey);
				return decryptedSessionKey;
			} catch (InvalidKeyException keyExp) {
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, KeymanagerConstant.REFERENCEID,
						"Error occurred because of mismatch with keys. Try with other current key for decryption. key Alias: " + alias);
				keyException = keyExp;
			} catch (InvalidDataException dataExp) {
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, KeymanagerConstant.REFERENCEID,
						"Error occurred because of mismatch with keys. Try with other current key for decryption. key Alias: " + alias);
				dataException = dataExp;
			}
		}
		if(keyException == null) 
			throw dataException;
			 
		throw keyException;
	}
}
