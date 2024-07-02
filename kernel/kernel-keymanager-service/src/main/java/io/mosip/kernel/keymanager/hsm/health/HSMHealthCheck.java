package io.mosip.kernel.keymanager.hsm.health;

import java.security.Key;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.core.logger.spi.Logger;
import reactor.core.publisher.Mono;

/**
 * Health Check for HSM server.
 * 
 * @author Mahammed Taheer
 *
 * @since 1.2.1
 */

@Component("HSMHealth")
public class HSMHealthCheck implements ReactiveHealthIndicator {
    
    private static final Logger LOGGER = KeymanagerLogger.getLogger(HSMHealthCheck.class);
    
    private static final String READ_KEY_SUCCESS = "READ_KEY_SUCCESS";

    private static final String ENCRYPT_OPS_SUCCESS = "ENCRYPT_OPS_SUCCESS";

    private static final String NO_UNIQUE_KEY_ALIAS_FOUND = "NO_UNIQUE_KEY_ALIAS_FOUND";

    private static final String HEALTH_CHECK_NOT_ENABLED = "HEALTH_CHECK_NOT_ENABLED";

    private static final String EMPTY_STR = "";

    private static final String SAMPLE_DATA = "Tk8tU0VDRVJULUFWQUlMQUJMRS1URU1QLUZJWElORy0";

    @Value("${mosip.kernel.keymgr.hsm.health.check.enabled:true}")
	private boolean healthCheckEnabled;

    @Value("${mosip.kernel.keymgr.hsm.health.check.encrypt:false}")
	private boolean healthCheckEncryptEnabled;

    @Value("${mosip.kernel.keymgr.hsm.health.key.app-id:KERNEL}")
	private String healthCheckDefaultAppId;

	@Value("${mosip.kernel.keymgr.hsm.healthkey.ref-id:IDENTITY_CACHE}")
    private String healthCheckDefaultRefId;

    @Value("${mosip.kernel.keymgr.hsm.health.check.algorithm-name:AES/ECB/NoPadding}")
	private String aesECBTransformation;

    private String cachedKeyAlias;

    @Autowired
	private KeymanagerDBHelper dbHelper;

    @Autowired
	private ECKeyStore keyStore;

    @Override
    public Mono<Health> health() {
        return Mono.fromCallable(() -> checkHSMHealth())
        .map(result -> {
            if (HEALTH_CHECK_NOT_ENABLED.equals(result)) {
                return Health.up().withDetail("Info: ", result).build();    
            }
            if (!READ_KEY_SUCCESS.equals(result) && !ENCRYPT_OPS_SUCCESS.equals(result)) {
                return Health.down().withDetail("Error: ", result).build();
            }
            return Health.up().withDetail("Info: ", result).build();
        });
    }

    private String checkHSMHealth() {

        try {
            if (!healthCheckEnabled) {
                return HEALTH_CHECK_NOT_ENABLED;
            }
            String keyAlias = getHealthCheckKeyAlias();
            if (keyAlias.equals(EMPTY_STR)) {
                return NO_UNIQUE_KEY_ALIAS_FOUND;
            }

            Key key = keyStore.getSymmetricKey(keyAlias);
            if (!healthCheckEncryptEnabled) {
                LOGGER.info(KeymanagerConstant.SESSIONID, "", "healthCheck",
                                        READ_KEY_SUCCESS + ", Key Algorithm: " + key.getAlgorithm());
                return READ_KEY_SUCCESS;
            }

            Cipher cipher = Cipher.getInstance(aesECBTransformation);

			byte[] secretDataBytes = CryptoUtil.decodeURLSafeBase64(SAMPLE_DATA);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipher.doFinal(secretDataBytes, 0, secretDataBytes.length);
            LOGGER.info(KeymanagerConstant.SESSIONID, "", "healthCheck",
                                ENCRYPT_OPS_SUCCESS + ", Key Algorithm: " + key.getAlgorithm());
            return ENCRYPT_OPS_SUCCESS;
        } catch (Throwable th) {
            return th.getMessage();
        }
        
    }

    private String getHealthCheckKeyAlias() {
        if (cachedKeyAlias != null) 
            return cachedKeyAlias;

        Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(healthCheckDefaultAppId,
        healthCheckDefaultRefId, DateUtils.getUTCCurrentDateTime());
        List<KeyAlias> currentKeyAliases = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
        if (currentKeyAliases.isEmpty() || currentKeyAliases.size() > 1) {
            return EMPTY_STR;
        }
        cachedKeyAlias = currentKeyAliases.get(0).getAlias();
        return cachedKeyAlias;
    }
    
}
