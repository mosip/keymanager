package io.mosip.kernel.keymanager.hsm.test.health;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.test.util.ReflectionTestUtils;

import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanager.hsm.health.HSMHealthCheck;
import reactor.core.publisher.Mono;

@RunWith(MockitoJUnitRunner.class)
public class HSMHealthCheckTest {

    @Mock
    private KeymanagerDBHelper dbHelper;

    @Mock
    private ECKeyStore keyStore;

    @InjectMocks
    private HSMHealthCheck hsmHealthCheck;

    @Before
    public void setup() {
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckDefaultAppId", "KERNEL");
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckDefaultRefId", "IDENTITY_CACHE");
        ReflectionTestUtils.setField(hsmHealthCheck, "aesECBTransformation", "AES/ECB/NoPadding");
        ReflectionTestUtils.setField(hsmHealthCheck, "cachedKeyAlias", null);
    }

    @Test
    public void testHealthUpWhenDisabled() {
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEnabled", false);
        Mono<Health> healthMono = hsmHealthCheck.health();
        Health health = healthMono.block();
        assertEquals(Status.UP, health.getStatus());
        assertEquals("HEALTH_CHECK_NOT_ENABLED", health.getDetails().get("Info: "));
    }

    @Test
    public void testHealthDownWhenNoKeyAliasFound() {
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEnabled", true);
        Map<String, List<KeyAlias>> emptyMap = new HashMap<>();
        emptyMap.put(KeymanagerConstant.CURRENTKEYALIAS, Collections.emptyList());
        when(dbHelper.getKeyAliases(any(), any(), any(LocalDateTime.class))).thenReturn(emptyMap);
        Mono<Health> healthMono = hsmHealthCheck.health();
        Health health = healthMono.block();
        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("NO_UNIQUE_KEY_ALIAS_FOUND", health.getDetails().get("Error: "));
    }

    @Test
    public void testHealthDownWhenMultipleKeyAliasesFound() {
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEnabled", true);
        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        List<KeyAlias> currentKeyAliases = new ArrayList<>();
        currentKeyAliases.add(new KeyAlias());
        currentKeyAliases.add(new KeyAlias());
        keyAliasMap.put(KeymanagerConstant.CURRENTKEYALIAS, currentKeyAliases);

        when(dbHelper.getKeyAliases(any(), any(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        Mono<Health> healthMono = hsmHealthCheck.health();
        Health health = healthMono.block();
        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("NO_UNIQUE_KEY_ALIAS_FOUND", health.getDetails().get("Error: "));
    }

    @Test
    public void testHealthUpWhenReadKeySuccess() throws Exception {
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEnabled", true);
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEncryptEnabled", false);

        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        List<KeyAlias> currentKeyAliases = new ArrayList<>();
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias("test-alias");
        currentKeyAliases.add(keyAlias);
        keyAliasMap.put(KeymanagerConstant.CURRENTKEYALIAS, currentKeyAliases);

        when(dbHelper.getKeyAliases(any(), any(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        Key key = new SecretKeySpec(new byte[16], "AES");
        when(keyStore.<Key>getSymmetricKey("test-alias")).thenReturn((SecretKey) key);

        Mono<Health> healthMono = hsmHealthCheck.health();
        Health health = healthMono.block();
        assertEquals(Status.UP, health.getStatus());
        assertEquals("READ_KEY_SUCCESS", health.getDetails().get("Info: "));
    }

    @Test
    public void testHealthUpWhenEncryptOpsSuccess() throws Exception {
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEnabled", true);
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEncryptEnabled", true);

        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        List<KeyAlias> currentKeyAliases = new ArrayList<>();
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias("test-alias");
        currentKeyAliases.add(keyAlias);
        keyAliasMap.put(KeymanagerConstant.CURRENTKEYALIAS, currentKeyAliases);

        when(dbHelper.getKeyAliases(any(), any(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        Key key = new SecretKeySpec(new byte[16], "AES");
        when(keyStore.<Key>getSymmetricKey("test-alias")).thenReturn((SecretKey) key);

        Mono<Health> healthMono = hsmHealthCheck.health();
        Health health = healthMono.block();
        assertEquals(Status.UP, health.getStatus());
        assertEquals("ENCRYPT_OPS_SUCCESS", health.getDetails().get("Info: "));
    }

    @Test
    public void testHealthDownWhenKeyStoreThrowsException() throws Exception {
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEnabled", true);
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEncryptEnabled", false);

        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        List<KeyAlias> currentKeyAliases = new ArrayList<>();
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias("test-alias");
        currentKeyAliases.add(keyAlias);
        keyAliasMap.put(KeymanagerConstant.CURRENTKEYALIAS, currentKeyAliases);

        when(dbHelper.getKeyAliases(any(), any(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        when(keyStore.<Key>getSymmetricKey("test-alias")).thenThrow(new RuntimeException("Keystore error"));

        Mono<Health> healthMono = hsmHealthCheck.health();
        Health health = healthMono.block();
        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("Keystore error", health.getDetails().get("Error: "));
    }

    @Test
    public void testHealthDownWhenEncryptionFails() throws Exception {
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEnabled", true);
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEncryptEnabled", true);

        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        List<KeyAlias> currentKeyAliases = new ArrayList<>();
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias("test-alias");
        currentKeyAliases.add(keyAlias);
        keyAliasMap.put(KeymanagerConstant.CURRENTKEYALIAS, currentKeyAliases);

        when(dbHelper.getKeyAliases(any(), any(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        // Using a key with a different algorithm to cause an encryption error
        Key key = new SecretKeySpec(new byte[16], "DES");
        when(keyStore.<Key>getSymmetricKey("test-alias")).thenReturn((SecretKey) key);

        Mono<Health> healthMono = hsmHealthCheck.health();
        Health health = healthMono.block();
        assertEquals(Status.UP, health.getStatus());
    }

    @Test
    public void testHealthUpWithCachedAlias() throws Exception {
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEnabled", true);
        ReflectionTestUtils.setField(hsmHealthCheck, "healthCheckEncryptEnabled", false);
        ReflectionTestUtils.setField(hsmHealthCheck, "cachedKeyAlias", "cached-alias");

        Key key = new SecretKeySpec(new byte[16], "AES");
        when(keyStore.<Key>getSymmetricKey("cached-alias")).thenReturn((SecretKey) key);

        Mono<Health> healthMono = hsmHealthCheck.health();
        Health health = healthMono.block();
        assertEquals(Status.UP, health.getStatus());
        assertEquals("READ_KEY_SUCCESS", health.getDetails().get("Info: "));
    }
}
