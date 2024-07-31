
package io.mosip.kernel.keymanagerservice.helper;

import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import jakarta.annotation.PostConstruct;

import org.cache2k.Cache;
import org.cache2k.Cache2kBuilder;
import org.cache2k.expiry.Expiry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
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

    // added because flag because getting exception in datasync.
    @Value("${mosip.kernel.keymanager.unique.identifier.autoupdate:true}")
	private boolean autoUpdate;

    @Value("${mosip.kernel.keymanager.key.cache.expire.inMins:1440}")
    private long cacheExpireInMins;

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
	ECKeyStore keyStore;

    /**
	 * {@link CryptomanagerUtils} instance
	 */
	@Autowired
	CryptomanagerUtils cryptomanagerUtil;

    private Cache<String, Optional<KeyPolicy>> keyPolicyCache = null;

    private Cache<String, List<KeyAlias>> keyAliasCache = null;

    @PostConstruct
    public void init() {
        if (autoUpdate) {
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, 
                        "Updating the thumbprint & key unique identifer in the table..");
            addCertificateThumbprints();
            addKeyUniqueIdentifier();
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, 
                        "Updating the thumbprint & key unique identifer completed.");
        }
        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, 
                        "Creating Cache object for key policy & Key Alias.");
        createCacheObject();
        createKeyAliasCacheObject();
        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, 
                        "Cache object for key policy & Key Alias creation completed.");
    }

    private void createCacheObject() {
        keyPolicyCache = new Cache2kBuilder<String, Optional<KeyPolicy>>() {}
        // added hashcode because test case execution failing with IllegalStateException: Cache already created
        .name("keyPolicyCache-" + this.hashCode()) 
        .eternal(true)
        .entryCapacity(20)
        .loaderThreadCount(1)
        .loader((keyPolicyName) -> {
                LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, 
                            "Fetching Key Policy for keyPolicyName(Cache): " + keyPolicyName);
                return keyPolicyRepository.findByApplicationId(keyPolicyName);
        })
        .build();
    }

    private void createKeyAliasCacheObject() {
        keyAliasCache = new Cache2kBuilder<String, List<KeyAlias>>() {}
        // added hashcode because test case execution failing with IllegalStateException: Cache already created
        .name("keyAliasCache-" + this.hashCode()) 
        .expireAfterWrite(cacheExpireInMins, TimeUnit.MINUTES)
        .entryCapacity(500)
        .refreshAhead(true)
        .loaderThreadCount(1)
        .loader((appIdRefId) -> {
                LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, 
                            "Fetching Key Alias for Application Id & Reference Id (Cache): " + appIdRefId);
                String[] appIdRefIdArr = appIdRefId.split(KeymanagerConstant.APP_REF_ID_SEP, -1);
                LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, 
                            "Key Alias for Application Id: " + appIdRefIdArr[0] + ", Reference Id (Cache): " 
                            + appIdRefIdArr[1]);
                return keyAliasRepository.findByApplicationIdAndReferenceId(appIdRefIdArr[0], appIdRefIdArr[1]);
        })
        .build();
    }
    
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
                            LocalDateTime expiryDateTime, String certThumbprint, String uniqueIdentifier) {
        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY, KeymanagerConstant.STOREKEYALIAS);
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias(alias);
        keyAlias.setApplicationId(applicationId);
        keyAlias.setReferenceId(referenceId);
        keyAlias.setKeyGenerationTime(timeStamp);
        keyAlias.setKeyExpiryTime(expiryDateTime);
        keyAlias.setCertThumbprint(certThumbprint);
        keyAlias.setUniqueIdentifier(uniqueIdentifier);
        keyAliasRepository.saveAndFlush(keymanagerUtil.setMetaData(keyAlias));
        purgeKeyAliasCache(applicationId, referenceId);
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
        String appIdRefIdKey = applicationId + KeymanagerConstant.APP_REF_ID_SEP + referenceId;
        List<KeyAlias> keyAliases = keyAliasCache.get(appIdRefIdKey).stream()
                .sorted((alias1, alias2) -> alias1.getKeyGenerationTime().compareTo(alias2.getKeyGenerationTime()))
                .collect(Collectors.toList());
        if (keyAliases.isEmpty()){
            LOGGER.info(KeymanagerConstant.SESSIONID, applicationId, referenceId, 
                    "Removing from Cache because empty keyAlias are getting added in Cache.");
            keyAliasCache.expireAt(appIdRefIdKey, Expiry.NOW);
        }
        int preExpireDays = getPreExpireDays(applicationId, referenceId);
        LOGGER.info(KeymanagerConstant.SESSIONID, applicationId, referenceId, "PreExpireDays found as key policy:" + preExpireDays);
        List<KeyAlias> currentKeyAliases = keyAliases.stream()
                .filter(keyAlias -> keymanagerUtil.isValidTimestamp(timeStamp, keyAlias, preExpireDays)).collect(Collectors.toList());
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
        Optional<KeyPolicy> keyPolicy = getKeyPolicyFromCache(applicationId);
        if (!keyPolicy.isPresent()) {
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYPOLICY, keyPolicy.toString(),
                    "Key Policy not found for this application Id. Throwing exception");
            throw new InvalidApplicationIdException(KeymanagerErrorConstant.APPLICATIONID_NOT_VALID.getErrorCode(),
                    KeymanagerErrorConstant.APPLICATIONID_NOT_VALID.getErrorMessage());
        }
        LocalDateTime policyExpiryTime = timeStamp.plusDays(keyPolicy.get().getValidityInDays());
        // Commented below logic, as its not required after implementing key per expire days logic.
        /* if (!keyAlias.isEmpty()) {
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
        } */
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
        Optional<KeyPolicy> keyPolicy = getKeyPolicyFromCache(applicationId);
		if (!keyPolicy.isPresent() || !keyPolicy.get().isActive()) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYPOLICY, keyPolicy.toString(),
					"Key Policy not found for this application Id. Key/CSR generation not allowed.");
			throw new InvalidApplicationIdException(KeymanagerErrorConstant.APPLICATIONID_NOT_VALID.getErrorCode(),
					KeymanagerErrorConstant.APPLICATIONID_NOT_VALID.getErrorMessage());
        }
        return keyPolicy;
    }

    public Optional<KeyPolicy> getKeyPolicyFromCache(String applicationId) {
        // added because regClient uses the autoupdate flag as false.
        if (Objects.isNull(keyPolicyCache)) {
            createCacheObject();
        }
        return keyPolicyCache.get(applicationId);
    }

    public KeyStore getKeyAlias(String certThumbprint, String appIdRefIdKey, String applicationId, String referenceId) {
        List<KeyAlias> keyAliases = keyAliasRepository.findByCertThumbprint(certThumbprint);
        if (keyAliases.isEmpty()) {
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                            "key alias not found for the provided thumbprint, may be cert thumbprint is not updated. Adding thumbprint(s) now.");
            addCertificateThumbprints();
            keyAliases = keyAliasRepository.findByCertThumbprint(certThumbprint);
        }
        if (keyAliases.isEmpty()) {
            // Still key not found after updating the thumbprints. So throwing exception.
            LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                    "no key alias found for the provided thumbprint after updating the thumbprints in DB. TP: " + certThumbprint);
            throw new KeymanagerServiceException(KeymanagerErrorConstant.KEY_NOT_FOUND_BY_THUMBPRINT.getErrorCode(),
                    KeymanagerErrorConstant.KEY_NOT_FOUND_BY_THUMBPRINT.getErrorMessage());
        }
        // Mostly should fetch only one object from DB, so considering as first preference.
        KeyAlias foundKeyAlias = keyAliases.get(0);
        if (keyAliases.size() > 1) {
            // Updated below logic because in case KM is used to perform both encryption/decryption. 
            // thumbprint for component certificate & Partner certificate will be same. Eg: RESIDENT (App Id)
            List<KeyAlias> keyAliasesWithAppId = keyAliasRepository.findByApplicationIdAndReferenceIdAndCertThumbprint(applicationId, 
                                                    referenceId, certThumbprint);
            if (keyAliasesWithAppId.size() > 1) {
                LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                    "More than one key alias found for the provided thumbprint.");
                throw new KeymanagerServiceException(KeymanagerErrorConstant.MORE_THAN_ONE_KEY_FOUND.getErrorCode(),
                    KeymanagerErrorConstant.MORE_THAN_ONE_KEY_FOUND.getErrorMessage());
            }
            foundKeyAlias = keyAliasesWithAppId.get(0);
        }

        // Duplicate check required because before caching comparison of app id & reference id is required.
        String foundDBAppIdRefId = foundKeyAlias.getApplicationId() + KeymanagerConstant.HYPHEN + foundKeyAlias.getReferenceId();
        // Checking for master key is used during encryption time. 
        String foundDBAppId = foundKeyAlias.getApplicationId();
        if (!foundDBAppIdRefId.equals(appIdRefIdKey) && !foundDBAppId.equals(applicationId)){
            LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                "AppId & Reference Id not matching with the input thumbprint value(helper).");
            throw new KeymanagerServiceException(KeymanagerErrorConstant.APP_ID_REFERENCE_ID_NOT_MATCHING.getErrorCode(),
                KeymanagerErrorConstant.APP_ID_REFERENCE_ID_NOT_MATCHING.getErrorMessage());
        }
        
        Optional<KeyStore> keyFromDBStore = getKeyStoreFromDB(foundKeyAlias.getAlias());
        if (!keyFromDBStore.isPresent()){
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                "Key not found in key store for the matched thumbprint. Might has used master key during encryption.");
            return new KeyStore(foundKeyAlias.getAlias(), null, null, null);
            
        }
        if (Objects.isNull(foundKeyAlias.getUniqueIdentifier())) {
            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                            "Key Unique identifier not found for the provided key, may be unique identifier is not updated. " +
                            "Adding Unique Identifier(s) now.");
            addKeyUniqueIdentifier();
        }
        return keyFromDBStore.get();
    }

    // this will get executed only one time to add the certificate thumbprints.
    private synchronized void addCertificateThumbprints() {
        List<KeyAlias> allKeyAliases = keyAliasRepository.findByCertThumbprintIsNull();
        allKeyAliases.stream().filter(keyAlias -> (Objects.isNull(keyAlias.getCertThumbprint()) || 
                                                    keyAlias.getCertThumbprint().equals(KeymanagerConstant.EMPTY)))
                                .forEach(keyAlias -> {
                                    try {
                                        if (keyAlias.getReferenceId().isEmpty() || 
                                            (keyAlias.getApplicationId().equals(signApplicationId) &&
                                                keyAlias.getReferenceId().equals(signRefId))) {
                                            String uniqueValue = keyAlias.getApplicationId() + KeymanagerConstant.UNDER_SCORE + 
                                                                keyAlias.getReferenceId() + KeymanagerConstant.UNDER_SCORE +
                                                                keyAlias.getKeyGenerationTime().format(KeymanagerConstant.DATE_FORMATTER);
                                            String uniqueIdentifier = keymanagerUtil.getUniqueIdentifier(uniqueValue);
                                            X509Certificate x509Cert = (X509Certificate) keyStore.getCertificate(keyAlias.getAlias());
                                            String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(x509Cert);
                                            storeKeyInAlias(keyAlias.getApplicationId(), keyAlias.getKeyGenerationTime(), keyAlias.getReferenceId(), 
                                                keyAlias.getAlias(), keyAlias.getKeyExpiryTime(), certThumbprint, uniqueIdentifier);
                                            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                                                    "Thumbprint added for the key alias: " + keyAlias.getAlias());
                                        }
                                        if (!keyAlias.getReferenceId().isEmpty()){
                                            Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = 
                                                    getKeyStoreFromDB(keyAlias.getAlias());
                                            if (keyFromDBStore.isPresent()) {
                                                String certificateData = keyFromDBStore.get().getCertificateData();
                                                X509Certificate x509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
                                                String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(x509Cert);
                                                String uniqueValue = keyAlias.getApplicationId() + KeymanagerConstant.UNDER_SCORE + 
                                                                keyAlias.getReferenceId() + KeymanagerConstant.UNDER_SCORE;
                                                Optional<KeyPolicy> keyPolicy = getKeyPolicyFromCache(keyAlias.getApplicationId());
                                                uniqueValue += keyPolicy.isPresent() ? 
                                                               keyAlias.getKeyGenerationTime().format(KeymanagerConstant.DATE_FORMATTER) :
                                                               certThumbprint;
                                                if (signApplicationId.equals(KeymanagerConstant.KERNEL_APP_ID) && 
                                                            (keyAlias.getApplicationId().equals(KeymanagerConstant.IDA_APP_ID) ||
                                                            keyAlias.getApplicationId().equals(KeymanagerConstant.PARTNER_APP_ID))) {
                                                    uniqueValue += keyAlias.getAlias();
                                                }
                                                String uniqueIdentifier = keymanagerUtil.getUniqueIdentifier(uniqueValue);
                                                storeKeyInAlias(keyAlias.getApplicationId(), keyAlias.getKeyGenerationTime(), 
                                                    keyAlias.getReferenceId(), keyAlias.getAlias(), keyAlias.getKeyExpiryTime(), 
                                                    certThumbprint, uniqueIdentifier);
                                                LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                                                    "Thumbprint added for the key alias: " + keyAlias.getAlias());
                                            }
                                        }
                                        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                                            "Thumbprint added for the key alias: " + keyAlias.getAlias());
                                    } catch(Throwable t) {
                                        // May be unique constraint exception from DB
                                        LOGGER.debug(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                                            "Error Adding Thumbprint for the key alias: " + keyAlias.getAlias());
                                    }
                                });
    }

    // this will get executed only one time to add the key unique identifier.
    private synchronized void addKeyUniqueIdentifier() {
        List<KeyAlias> allKeyAliases = keyAliasRepository.findByUniqueIdentifierIsNull();
        allKeyAliases.stream().filter(keyAlias -> (Objects.isNull(keyAlias.getUniqueIdentifier()) || 
                                                    keyAlias.getUniqueIdentifier().equals(KeymanagerConstant.EMPTY)))
                                .forEach(keyAlias -> {
                                    try {
                                        if (keyAlias.getReferenceId().isEmpty() || 
                                            (keyAlias.getApplicationId().equals(signApplicationId) &&
                                                keyAlias.getReferenceId().equals(signRefId))) {
                                            String uniqueValue = keyAlias.getApplicationId() + KeymanagerConstant.UNDER_SCORE + 
                                                    keyAlias.getReferenceId() + KeymanagerConstant.UNDER_SCORE +
                                                    keyAlias.getKeyGenerationTime().format(KeymanagerConstant.DATE_FORMATTER);
                                            String uniqueIdentifier = keymanagerUtil.getUniqueIdentifier(uniqueValue);
                                            storeKeyInAlias(keyAlias.getApplicationId(), keyAlias.getKeyGenerationTime(), keyAlias.getReferenceId(), 
                                                keyAlias.getAlias(), keyAlias.getKeyExpiryTime(), keyAlias.getCertThumbprint(), uniqueIdentifier);
                                            LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                                                "Unique Identifier added for the key alias: " + keyAlias.getAlias());
                                        }
                                        if (!keyAlias.getReferenceId().isEmpty()){
                                            Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = 
                                                    getKeyStoreFromDB(keyAlias.getAlias());
                                            if (keyFromDBStore.isPresent()) {
                                                String uniqueValue = keyAlias.getApplicationId() + KeymanagerConstant.UNDER_SCORE + 
                                                                    keyAlias.getReferenceId() + KeymanagerConstant.UNDER_SCORE;
                                                Optional<KeyPolicy> keyPolicy = getKeyPolicyFromCache(keyAlias.getApplicationId());
                                                uniqueValue += keyPolicy.isPresent() ? 
                                                                keyAlias.getKeyGenerationTime().format(KeymanagerConstant.DATE_FORMATTER) :
                                                                keyAlias.getCertThumbprint();
                                                if (signApplicationId.equals(KeymanagerConstant.KERNEL_APP_ID) && 
                                                            (keyAlias.getApplicationId().equals(KeymanagerConstant.IDA_APP_ID) ||
                                                            keyAlias.getApplicationId().equals(KeymanagerConstant.PARTNER_APP_ID))) {
                                                    uniqueValue += keyAlias.getAlias();
                                                }        
                                                String uniqueIdentifier = keymanagerUtil.getUniqueIdentifier(uniqueValue);
                                                storeKeyInAlias(keyAlias.getApplicationId(), keyAlias.getKeyGenerationTime(), 
                                                    keyAlias.getReferenceId(), keyAlias.getAlias(), keyAlias.getKeyExpiryTime(), 
                                                    keyAlias.getCertThumbprint(), uniqueIdentifier);
                                                
                                            }
                                        }
                                        LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                                            "Unique Identifier added for the key alias: " + keyAlias.getAlias());
                                    } catch(Throwable t) {
                                        // May be unique constraint exception from DB
                                        LOGGER.debug(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
                                            "Error Adding Unique Identifier for the key alias: " + keyAlias.getAlias());
                                    }
                                });
    }

    private int getPreExpireDays(String applicationId, String referenceId){
        Optional<KeyPolicy> keyPolicy = getKeyPolicyFromCache(applicationId);
        if (!keyPolicy.isPresent()) {
            // key policy details not available, so not considering any pre expire days 
            return 0;
        }
        
        if (referenceId.isEmpty() || (applicationId.equals(signApplicationId) &&
                        (referenceId.equals(signRefId) || referenceId.equals(KeymanagerConstant.KERNEL_IDENTIFY_CACHE)))) {
            // key policy details for component Master Key.
            return keyPolicy.get().getPreExpireDays();
        }
        // finally, considering key policy for encryption keys.
        Optional<KeyPolicy> encKeyPolicy = getKeyPolicyFromCache(KeymanagerConstant.BASE_KEY_POLICY_CONST);
        if (!encKeyPolicy.isPresent()) {
            // key policy details not available for encryption key, so defaulting to 30 days 
            return 30;
        }
        return encKeyPolicy.get().getPreExpireDays();
    }

    private void purgeKeyAliasCache(String applicationId, String referenceId) {
        String appIdRefIdKey = applicationId + KeymanagerConstant.APP_REF_ID_SEP + referenceId;
        LOGGER.info(KeymanagerConstant.SESSIONID, applicationId, referenceId, 
                    "Purging from Cache because new key generated or new certificate uploaded." +
                    "AppId & RefId: " + appIdRefIdKey);
        keyAliasCache.expireAt(appIdRefIdKey, Expiry.NOW);
    }
}
