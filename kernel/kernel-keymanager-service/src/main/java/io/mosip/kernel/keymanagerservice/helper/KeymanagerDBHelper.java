package io.mosip.kernel.keymanagerservice.helper;

import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.entity.KeyPolicy;
import io.mosip.kernel.keymanagerservice.entity.KeyStore;
import io.mosip.kernel.keymanagerservice.exception.InvalidApplicationIdException;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyPolicyRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyStoreRepository;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;

/**
 * DB Helper class for Keymanager
 * 
 * @author Mahammed Taheer
 * @since 1.1.2
 *
 */

@Component
public class KeymanagerDBHelper {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(KeymanagerDBHelper.class);

    /** The sign applicationid. */
	@Value("${mosip.sign.applicationid:KERNEL}")
	private String signApplicationId;

    @Value("${mosip.sign-certificate-refid:SIGN}")
	private String signRefId;
    /**
	 * {@link KeyAliasRepository} instance
	 */
	@Autowired
	KeyAliasRepository keyAliasRepository;

	/**
	 * {@link KeyPolicyRepository} instance
	 */
	@Autowired
	KeyPolicyRepository keyPolicyRepository;

	/**
	 * {@link KeyStoreRepository} instance
	 */
	@Autowired
	KeyStoreRepository keyStoreRepository;

	/**
	 * Utility to generate Metadata
	 */
	@Autowired
    KeymanagerUtil keymanagerUtil;

    /**
	 * Keystore instance to handles and store cryptographic keys.
	 */
	@Autowired
	io.mosip.kernel.core.keymanager.spi.KeyStore keyStore;

    /**
	 * {@link CryptomanagerUtils} instance
	 */
	@Autowired
	CryptomanagerUtils cryptomanagerUtil;
    
    /**
	 * Function to store key in keyalias table
	 * 
	 * @param applicationId  applicationId
	 * @param timeStamp      timeStamp
	 * @param referenceId    referenceId
	 * @param alias          alias
	 * @param expiryDateTime expiryDateTime
	 */
	public void storeKeyInAlias(String applicationId, LocalDateTime timeStamp, String referenceId, String alias,
                            LocalDateTime expiryDateTime, String certThumbprint) {
        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, KeymanagerConstant.STOREKEYALIAS);
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias(alias);
        keyAlias.setApplicationId(applicationId);
        keyAlias.setReferenceId(referenceId);
        keyAlias.setKeyGenerationTime(timeStamp);
        keyAlias.setKeyExpiryTime(expiryDateTime);
        keyAlias.setCertThumbprint(certThumbprint);
        keyAliasRepository.saveAndFlush(keymanagerUtil.setMetaData(keyAlias));
    }

    /**
    * Function to store key in DB store
    * 
    * @param alias               alias
    * @param masterAlias         masterAlias
    * @param publicKey           publicKey
    * @param encryptedPrivateKey encryptedPrivateKey
    */
    public void storeKeyInDBStore(String alias, String masterAlias, String certificateData, String encryptedPrivateKey) {
        KeyStore dbKeyStore = new KeyStore();
        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, KeymanagerConstant.STOREDBKEY);
        dbKeyStore.setAlias(alias);
        dbKeyStore.setMasterAlias(masterAlias);
        dbKeyStore.setCertificateData(certificateData);
        dbKeyStore.setPrivateKey(encryptedPrivateKey);
        keyStoreRepository.saveAndFlush(keymanagerUtil.setMetaData(dbKeyStore));
    }

    /**
	 * Function to get keyalias from keyalias table
	 * 
	 * @param applicationId applicationId
	 * @param referenceId   referenceId
	 * @param timeStamp     timeStamp
	 * @return a map containing a list of all keyalias matching applicationId and
	 *         referenceId with key "keyAlias"; and a list of all keyalias with
	 *         matching timestamp with key "currentKeyAlias"
	 */
	public Map<String, List<KeyAlias>> getKeyAliases(String applicationId, String referenceId, LocalDateTime timeStamp) {
        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, KeymanagerConstant.GETALIAS);
        Map<String, List<KeyAlias>> hashmap = new HashMap<>();
        List<KeyAlias> keyAliases = keyAliasRepository.findByApplicationIdAndReferenceId(applicationId, referenceId)
                .stream()
                .sorted((alias1, alias2) -> alias1.getKeyGenerationTime().compareTo(alias2.getKeyGenerationTime()))
                .collect(Collectors.toList());
        List<KeyAlias> currentKeyAliases = keyAliases.stream()
                .filter(keyAlias -> keymanagerUtil.isValidTimestamp(timeStamp, keyAlias)).collect(Collectors.toList());
        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS, Arrays.toString(keyAliases.toArray()),
                KeymanagerConstant.KEYALIAS);
        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
                Arrays.toString(currentKeyAliases.toArray()), KeymanagerConstant.CURRENTKEYALIAS);
        hashmap.put(KeymanagerConstant.KEYALIAS, keyAliases);
        hashmap.put(KeymanagerConstant.CURRENTKEYALIAS, currentKeyAliases);
        return hashmap;
    }

    /**
    * Function to get expiry datetime using keypolicy table. If a overlapping key
    * exists for same time interval, then expiry datetime of current key will be
    * till generation datetime of overlapping key
    * 
    * @param applicationId applicationId
    * @param timeStamp     timeStamp
    * @param keyAlias      keyAlias
    * @return expiry datetime
    */
    public LocalDateTime getExpiryPolicy(String applicationId, LocalDateTime timeStamp, List<KeyAlias> keyAlias) {
        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, applicationId,
                KeymanagerConstant.GETEXPIRYPOLICY);
        Optional<KeyPolicy> keyPolicy = keyPolicyRepository.findByApplicationId(applicationId);
        if (!keyPolicy.isPresent()) {
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYPOLICY, keyPolicy.toString(),
                    "Key Policy not found for this application Id. Throwing exception");
            throw new InvalidApplicationIdException(KeymanagerErrorConstant.APPLICATIONID_NOT_VALID.getErrorCode(),
                    KeymanagerErrorConstant.APPLICATIONID_NOT_VALID.getErrorMessage());
        }
        LocalDateTime policyExpiryTime = timeStamp.plusDays(keyPolicy.get().getValidityInDays());
        if (!keyAlias.isEmpty()) {
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS, String.valueOf(keyAlias.size()),
                    "Getting expiry policy. KeyAlias exists");
            for (KeyAlias alias : keyAlias) {
                if (keymanagerUtil.isOverlapping(timeStamp, policyExpiryTime, alias.getKeyGenerationTime(),
                        alias.getKeyExpiryTime())) {
                    LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                            "Overlapping timestamp found. Changing policyExpiryTime");
                    policyExpiryTime = alias.getKeyGenerationTime().minusSeconds(1);
                    break;
                }
            }
        }
        return policyExpiryTime;
    }

    /**
    * Function to fetch Keystore from DB.
    * 
    * @param keyAlias   alias of the key.
    * @return KeyStore {@KeyStore}
    */
    public Optional<KeyStore> getKeyStoreFromDB(String keyAlias) {
        Optional<KeyStore> dbKeyStore = keyStoreRepository.findByAlias(keyAlias);
        /* if (!dbKeyStore.isPresent()) {
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.DBKEYSTORE, dbKeyStore.toString(),
                    "Key in DB Store does not exists. Throwing exception");
            throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(), KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
        } */
        return dbKeyStore;
    }
    
    /**
    * Function to fetch KeyPolicy from DB.
    * 
    * @param applicationId   App Id of the key.
    * @return KeyPolicy {@KeyPolicy}
    */
    public Optional<KeyPolicy> getKeyPolicy(String applicationId){
        Optional<KeyPolicy> keyPolicy = keyPolicyRepository.findByApplicationIdAndIsActive(applicationId, true);
		if (!keyPolicy.isPresent()) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYPOLICY, keyPolicy.toString(),
					"Key Policy not found for this application Id.");
			throw new InvalidApplicationIdException(KeymanagerErrorConstant.APPLICATIONID_NOT_VALID.getErrorCode(),
					KeymanagerErrorConstant.APPLICATIONID_NOT_VALID.getErrorMessage());
        }
        return keyPolicy;
    }

    public KeyStore getKeyAlias(String certThumbprint, String appIdRefIdKey) {
        List<KeyAlias> keyAliases = keyAliasRepository.findByCertThumbprint(certThumbprint);
        if (keyAliases.isEmpty()) {
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                            "key alias not found for the provided thumbprint, may be cert thumbprint is not updated. Adding thumbprint(s) now.");
            addCertificateThumbprints();
            keyAliases = keyAliasRepository.findByCertThumbprint(certThumbprint);
        }
        if (keyAliases.size() > 1) {
            LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                "More than one key alias found for the provided thumbprint.");
            throw new KeymanagerServiceException(KeymanagerErrorConstant.MORE_THAN_ONE_KEY_FOUND.getErrorCode(),
                KeymanagerErrorConstant.MORE_THAN_ONE_KEY_FOUND.getErrorMessage());
        }
        // Duplicate check required because before cacheing comparison of app id & reference id is required.
        String idKey = keyAliases.get(0).getApplicationId() + KeymanagerConstant.HYPHEN + keyAliases.get(0).getReferenceId();
        // Checking for master key is used during encryption time. 
        String idCompMasterKey = keyAliases.get(0).getApplicationId() + KeymanagerConstant.HYPHEN;
        if (!idKey.equals(appIdRefIdKey) && !idCompMasterKey.equals(idKey)){
            LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                "AppId & Reference Id not matching with the input thumbprint value(helper).");
            throw new KeymanagerServiceException(KeymanagerErrorConstant.APP_ID_REFERENCE_ID_NOT_MATCHING.getErrorCode(),
                KeymanagerErrorConstant.APP_ID_REFERENCE_ID_NOT_MATCHING.getErrorMessage());
        }
        Optional<KeyStore> keyFromDBStore = getKeyStoreFromDB(keyAliases.get(0).getAlias());
        if (!keyFromDBStore.isPresent()){
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                "Key not found in key store for the matched thumbprint. Might has used master key during encryption.");
            return new KeyStore(keyAliases.get(0).getAlias(), null, null, null);
            
        }
        return keyFromDBStore.get();
    }

    // this will get executed only one time to add the certificate thumbprints.
    private synchronized void addCertificateThumbprints() {
        List<KeyAlias> allKeyAliases = keyAliasRepository.findAll();
        allKeyAliases.stream().filter(keyAlias -> ((Objects.isNull(keyAlias.getCertThumbprint()) || 
                                                    keyAlias.getCertThumbprint().equals(KeymanagerConstant.EMPTY)) && 
                                                    !keyAlias.getApplicationId().equals(signApplicationId) &&
                                                    !keyAlias.getReferenceId().equals(KeymanagerConstant.KERNEL_IDENTIFY_CACHE)))
                                .forEach(keyAlias -> {
                                    if (keyAlias.getReferenceId().isEmpty() || 
                                        (keyAlias.getApplicationId().equals(signApplicationId) &&
                                            keyAlias.getReferenceId().equals(signRefId))) {
                                        X509Certificate x509Cert = (X509Certificate) keyStore.getCertificate(keyAlias.getAlias());
                                        String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(x509Cert);
                                        storeKeyInAlias(keyAlias.getApplicationId(), keyAlias.getKeyGenerationTime(), keyAlias.getReferenceId(), 
                                            keyAlias.getAlias(), keyAlias.getKeyExpiryTime(), certThumbprint);
                                    }
                                    if (!keyAlias.getReferenceId().isEmpty()){
                                        Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = 
                                                getKeyStoreFromDB(keyAlias.getAlias());
                                        if (keyFromDBStore.isPresent()) {
                                            String certificateData = keyFromDBStore.get().getCertificateData();
                                            X509Certificate x509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
                                            String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(x509Cert);
                                            storeKeyInAlias(keyAlias.getApplicationId(), keyAlias.getKeyGenerationTime(), 
                                                keyAlias.getReferenceId(), keyAlias.getAlias(), keyAlias.getKeyExpiryTime(), certThumbprint);
                                        }
                                    }
                                    LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                                        "Thumbprint added for the key alias: " + keyAlias.getAlias());
                                });
    }
}