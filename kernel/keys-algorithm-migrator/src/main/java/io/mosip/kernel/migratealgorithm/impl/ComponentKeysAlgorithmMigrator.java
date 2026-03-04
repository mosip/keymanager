package io.mosip.kernel.migratealgorithm.impl;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class ComponentKeysAlgorithmMigrator {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(ComponentKeysAlgorithmMigrator.class);

    private static final String ROOT_APP_ID = "ROOT";

    private static final String BLANK_REF_ID = "";

    private static final String OBJECT_TYPE = "CSR";

    @Value("${mosip.kernel.keymanager.algorithm.migrate.appids.list}")
    private String appIdsList;

    @Autowired
    KeymanagerDBHelper dbHelper;

    @Autowired
    KeymanagerService keymanagerService;

    public void migrateAlgorithm() {
        LOGGER.info("Starting Key Manager Invalidating ROOT and Component Keys...");
        rotateMasterKeys();
        LOGGER.info("Completed Key Manager Invalidating ROOT and Component Keys...");
    }

    private void rotateMasterKeys() {
        LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
        Map<String, List<KeyAlias>> rootKeyAliasMap = dbHelper.getKeyAliases(ROOT_APP_ID, BLANK_REF_ID, timestamp);
        List<KeyAlias> currentKeyAlias = rootKeyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
        LOGGER.info("Invalidating ROOT master key...");
        invalidateKeyAlias(ROOT_APP_ID, BLANK_REF_ID, currentKeyAlias, timestamp);
        LOGGER.info("ROOT master key invalidation completed.");

        LOGGER.info("Generating ROOT master key...");
        generateMasterKey(ROOT_APP_ID, BLANK_REF_ID);
        LOGGER.info("ROOT master key generation completed.");

        List<Map.Entry<String, String>> componentKeysList = getMasterKeysList();
        componentKeysList.forEach(entry -> {
            String appId = entry.getKey();
            String refId = entry.getValue();
            try {
                LOGGER.info("Invalidating master key for AppId: " + appId + " RefId: " + refId);
                Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(appId, refId, timestamp);
                List<KeyAlias> currentKeyAliasList = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
                invalidateKeyAlias(appId, refId, currentKeyAliasList, timestamp);
                LOGGER.info("Master key invalidation completed for AppId: " + appId + " RefId: " + refId);

                LOGGER.info("Generating master key for AppId: " + appId + " RefId: " + refId);
                generateMasterKey(appId, refId);
                LOGGER.info("Master key generation completed for AppId: " + appId + " RefId: " + refId);
            } catch (Exception e) {
                LOGGER.error("Error invalidating master key for AppId: " + appId + " RefId: " + refId + " Error: "
                        + e.getMessage());
            }
        });
    }

    private void generateMasterKey(String appId, String refId) {
        LOGGER.info("Generating Key using Service directly for AppId: " + appId + ", RefId: " + refId);

        KeyPairGenerateRequestDto requestDto = new KeyPairGenerateRequestDto();
        requestDto.setApplicationId(appId);
        requestDto.setReferenceId(refId);

        try {
            // Calling the keymanager service to generate master key
            keymanagerService.generateMasterKey(OBJECT_TYPE, requestDto);
            LOGGER.info("Key Generation Successful for AppId: " + appId);
        } catch (Exception e) {
            LOGGER.error("Error calling generate master key API for AppId: " + appId + " Error: " + e.getMessage());
            throw e;
        }
    }

    private List<Map.Entry<String, String>> getMasterKeysList() {
        if (appIdsList == null || appIdsList.isEmpty()) {
            return Collections.emptyList();
        }
        return Stream.of(appIdsList.split(","))
                .map(String::trim)
                .filter(entry -> !entry.equalsIgnoreCase(ROOT_APP_ID))
                .map(entry -> {
                    if (entry.contains(":")) {
                        String[] parts = entry.split(":");
                        return new AbstractMap.SimpleEntry<>(parts[0].trim(), parts[1].trim());
                    } else {
                        return new AbstractMap.SimpleEntry<>(entry, BLANK_REF_ID);
                    }
                })
                .filter(entry -> !(KeymanagerConstant.KERNEL_APP_ID.equalsIgnoreCase(entry.getKey()) &&
                        KeymanagerConstant.KERNEL_IDENTIFY_CACHE.equalsIgnoreCase(entry.getValue())))
                .collect(Collectors.toList());
    }

    private void invalidateKeyAlias(String appId, String refId, List<KeyAlias> keyAliasList, LocalDateTime timestamp) {
        LocalDateTime expireTime = timestamp.minusMinutes(1L);
        keyAliasList.forEach(alias -> {
            dbHelper.storeKeyInAlias(appId, alias.getKeyGenerationTime(), refId, alias.getAlias(),
                    expireTime, alias.getCertThumbprint(), alias.getUniqueIdentifier());
        });
    }
}
