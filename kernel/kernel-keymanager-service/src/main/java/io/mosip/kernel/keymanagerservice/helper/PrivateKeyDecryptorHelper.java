package io.mosip.kernel.keymanagerservice.helper;

import java.security.KeyFactory;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import io.mosip.kernel.core.crypto.exception.InvalidKeyException;
import io.mosip.kernel.core.crypto.exception.NullDataException;
import io.mosip.kernel.core.crypto.exception.NullKeyException;
import io.mosip.kernel.core.crypto.exception.NullMethodException;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.entity.KeyStore;
import io.mosip.kernel.keymanagerservice.exception.CryptoException;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;

/**
 * Private key decryption Helper class for Keymanager
 * 
 * @author Mahammed Taheer
 * @since 1.2.1
 *
 */
@Component
public class PrivateKeyDecryptorHelper {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(PrivateKeyDecryptorHelper.class);

    private Map<String, io.mosip.kernel.keymanagerservice.entity.KeyStore> cacheKeyStore = new ConcurrentHashMap<>();

	private Map<String, String> cacheReferenceIds = new ConcurrentHashMap<>();

    /**
	 * Utility to generate Metadata
	 */
	@Autowired
	KeymanagerUtil keymanagerUtil;

    @Autowired
	private KeymanagerDBHelper dbHelper;

    @Autowired
	private ECKeyStore keyStore;

    public KeyStore getDBKeyStoreData (String certThumbprintHex, String applicationId, String referenceId) {

        KeyStore dbKeyStore = cacheKeyStore.getOrDefault(certThumbprintHex, null);

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
            LOGGER.error(KeymanagerConstant.SESSIONID, this.getClass().getSimpleName(), KeymanagerConstant.EMPTY,
                "Application Id & Reference ID not matching with the input thumbprint value(decrypt).");
            throw new KeymanagerServiceException(KeymanagerErrorConstant.APP_ID_REFERENCE_ID_NOT_MATCHING.getErrorCode(),
                KeymanagerErrorConstant.APP_ID_REFERENCE_ID_NOT_MATCHING.getErrorMessage());
        }
        return dbKeyStore;
    }

    public Object[] getKeyObjects(KeyStore dbKeyStore, boolean fetchMasterKey) {
		
		String ksAlias = dbKeyStore.getAlias();

		String privateKeyObj = dbKeyStore.getPrivateKey();
		if (Objects.isNull(privateKeyObj)) {
            if (!fetchMasterKey) {
                LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Not Allowed to perform decryption with the master key.");
			    throw new KeymanagerServiceException(KeymanagerErrorConstant.DECRYPTION_NOT_ALLOWED.getErrorCode(),
					KeymanagerErrorConstant.DECRYPTION_NOT_ALLOWED.getErrorMessage());
            }
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
	}
    
}
