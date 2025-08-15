package io.mosip.kernel.keygenerator.generator;

import java.security.Key;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.entity.DataEncryptKeystore;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.repository.DataEncryptKeystoreRepository;
import jakarta.annotation.PostConstruct;

/**
 * The Class MasterKeysGenerator.
 *
 * @author Mahammed Taheer
 */
@SuppressWarnings("restriction")
@Component
public class RandomKeysGenerator {

    private static final Logger LOGGER = Logger.getLogger(RandomKeysGenerator.class.getName());

    private static final String CREATED_BY = "System";

    private static final String WRAPPING_TRANSFORMATION = "AES/ECB/NoPadding"; // NOSONAR using the key wrapping

    @Value("${zkcrypto.random.key.generate.count}")
    private long noOfKeysRequire;

    /**
     * Keystore instance to handles and store cryptographic keys.
     */
    @Autowired
    private ECKeyStore keyStore;

    @Autowired
    private KeymanagerDBHelper dbHelper;

    @Autowired
    DataEncryptKeystoreRepository dataEncryptKeystoreRepository;

    private static ThreadLocal<SecureRandom> secureRandomThreadLocal = null;

    private ThreadLocal<KeyGenerator> KEY_GENETRATOR;

    private ThreadLocal<Cipher> CIPHER_AES_ECB_NO_PADDING;

	@PostConstruct
	public void init() {
		secureRandomThreadLocal = ThreadLocal.withInitial(SecureRandom::new);
    
		KEY_GENETRATOR = ThreadLocal.withInitial(() -> {
    		try {
    			return KeyGenerator.getInstance("AES");
    		} catch (Exception e) {
    			throw new IllegalStateException("Unable to initialize KeyGenerator with AES", e);
    		}
    	});

		CIPHER_AES_ECB_NO_PADDING = ThreadLocal.withInitial(() -> {
    		try {
    			return Cipher.getInstance(WRAPPING_TRANSFORMATION);
    		} catch (Exception e) {
    			throw new IllegalStateException("Unable to initialize Cipher with AES/ECB/NoPadding", e);
    		}
    	});
	}

	@PreDestroy
	public void shutdown() {
		if (secureRandomThreadLocal != null)
			secureRandomThreadLocal.remove();

		if (KEY_GENETRATOR != null)
			KEY_GENETRATOR.remove();

		if (CIPHER_AES_ECB_NO_PADDING != null)
			CIPHER_AES_ECB_NO_PADDING.remove();
	}

	public void generateRandomKeys(String appId, String referenceId) {

        LocalDateTime localDateTimeStamp = DateUtils.getUTCCurrentDateTime();
        Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(appId, referenceId, localDateTimeStamp);
        List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
        String alias = null;
        if (currentKeyAlias.isEmpty()) {
            LOGGER.info("Cache Master key not available, generating new key.");
            alias = UUID.randomUUID().toString();
            generateAndStore(appId, referenceId, alias, localDateTimeStamp);
        } else {
            alias = currentKeyAlias.get(0).getAlias();
        }
        try {
            generate10KKeysAndStoreInDB(alias);
        } catch (Exception e) {
            LOGGER.warning("Error generating Random Keys." + e.getMessage());
        }
    }

    private void generateAndStore(String appId, String referenceId, String keyAlias, LocalDateTime localDateTimeStamp) {
		keyStore.generateAndStoreSymmetricKey(keyAlias);
        dbHelper.storeKeyInAlias(appId, localDateTimeStamp, referenceId, keyAlias, localDateTimeStamp.plusDays(1825), null, null);
    }
    
    private void generate10KKeysAndStoreInDB(String cacheMasterKeyAlias) throws Exception {
		
        int noOfActiveKeys = (int) dataEncryptKeystoreRepository.findAll().stream()
                                    .filter(k->k.getKeyStatus().equals("active")).count();			
		int noOfKeysToGenerate = 0;
		if((noOfKeysRequire-noOfActiveKeys) > 0) {
			noOfKeysToGenerate = (int) (noOfKeysRequire-noOfActiveKeys);
		}
		
		LOGGER.info("No Of Keys To Generate:" + noOfKeysToGenerate);
		
		Long maxid = dataEncryptKeystoreRepository.findMaxId();
		int startIndex = maxid == null ? 0 : maxid.intValue() + 1;
        
        SecureRandom rand = secureRandomThreadLocal.get();
		KeyGenerator keyGenerator = KEY_GENETRATOR.get();
        Cipher cipher = CIPHER_AES_ECB_NO_PADDING.get(); // NOSONAR using the key wrapping
        Key masterKey = keyStore.getSymmetricKey(cacheMasterKeyAlias);

		for (int i = startIndex; i < noOfKeysToGenerate; i++) {
			keyGenerator.init(256, rand);
			SecretKey sKey = keyGenerator.generateKey();
			cipher.init(Cipher.ENCRYPT_MODE, masterKey);
			byte[] wrappedKey = cipher.doFinal(sKey.getEncoded());
			String encodedKey = Base64.getEncoder().encodeToString(wrappedKey);
			insertKeyIntoTable(i, encodedKey, "Active");
			LOGGER.info("Insert secrets in DB: " + i);
		}
	}

	private void insertKeyIntoTable(int id, String secretData, String status) throws Exception {
		DataEncryptKeystore data = new DataEncryptKeystore();
		data.setId(id);
		data.setKey(secretData);
		data.setKeyStatus(status);
		data.setCrBy(CREATED_BY);
		data.setCrDTimes(LocalDateTime.now());
		dataEncryptKeystoreRepository.save(data);
	}
}
