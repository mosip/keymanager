package io.mosip.kernel.keymigrate.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
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
import org.springframework.test.util.ReflectionTestUtils;

import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import io.mosip.kernel.core.crypto.exception.InvalidKeyException;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;
import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;

import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keymanagerservice.entity.DataEncryptKeystore;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.exception.NoUniqueAliasException;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.repository.DataEncryptKeystoreRepository;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.keymigrate.constant.KeyMigratorConstants;
import io.mosip.kernel.keymigrate.dto.KeyMigrateBaseKeyRequestDto;
import io.mosip.kernel.keymigrate.dto.KeyMigrateBaseKeyResponseDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyDataDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyMigrateCertficateResponseDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyMigrateRequestDto;
import io.mosip.kernel.keymigrate.dto.ZKKeyMigrateResponseDto;
import io.mosip.kernel.keymigrate.service.impl.KeyMigratorServiceImpl;

@RunWith(MockitoJUnitRunner.class)
public class KeyMigratorServiceTest {

    @InjectMocks
    private KeyMigratorServiceImpl keyMigratorService;

    @Mock
    private KeymanagerDBHelper dbHelper;

    @Mock
    private KeymanagerUtil keymanagerUtil;

    @Mock
    private ECKeyStore keyStore;

    @Mock
    private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

    @Mock
    private DataEncryptKeystoreRepository dataEncryptKeystoreRepository;

    @Mock
    private CryptomanagerUtils cryptomanagerUtil;

    @Mock
    private KeyAliasRepository keyAliasRepository;

    private KeyPair keyPair;

    @Mock
    private X509Certificate mockCertificate;

    @Mock
    private CertificateParameters mockCertificateParameters;

    @Before
    public void setUp() throws Exception {
        ReflectionTestUtils.setField(keyMigratorService, "pmsSignAppId", "PMS");
        ReflectionTestUtils.setField(keyMigratorService, "signAlgorithm", "SHA256withRSA");
        ReflectionTestUtils.setField(keyMigratorService, "masterKeyAppId", "KERNEL");
        ReflectionTestUtils.setField(keyMigratorService, "masterKeyRefId", "IDENTITY_CACHE");
        ReflectionTestUtils.setField(keyMigratorService, "aesECBTransformation", "AES/ECB/NoPadding");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    // ==================== migrateBaseKey Tests ====================

    @Test
    public void testMigrateBaseKeySuccess() {
        KeyMigrateBaseKeyRequestDto requestDto = new KeyMigrateBaseKeyRequestDto();
        requestDto.setApplicationId("REGISTRATION");
        requestDto.setReferenceId("REF_123");
        requestDto.setEncryptedKeyData("encrypted-data");
        requestDto.setCertificateData("cert-data");
        requestDto.setNotBefore(LocalDateTime.now());
        requestDto.setNotAfter(LocalDateTime.now().plusDays(1));

        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias("master-key-alias");
        keyAliasMap.put("currentKeyAlias", Collections.singletonList(keyAlias));

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        when(keymanagerUtil.convertToCertificate(anyString())).thenReturn(mockCertificate);
        when(cryptomanagerUtil.getCertificateThumbprintInHex(any(X509Certificate.class))).thenReturn("thumbprint");
        when(keyAliasRepository.findByApplicationIdAndReferenceIdAndCertThumbprint(anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());
        when(keymanagerUtil.getUniqueIdentifier(anyString())).thenReturn("unique-id");

        KeyMigrateBaseKeyResponseDto response = keyMigratorService.migrateBaseKey(requestDto);

        assertNotNull(response);
        assertEquals(KeyMigratorConstants.MIGRAION_SUCCESS, response.getStatus());
        assertNotNull(response.getTimestamp());
        verify(dbHelper, times(1)).storeKeyInDBStore(anyString(), eq("master-key-alias"), anyString(), anyString());
        verify(dbHelper, times(1)).storeKeyInAlias(anyString(), any(LocalDateTime.class), anyString(),
                anyString(), any(LocalDateTime.class), anyString(), anyString());
    }

    @Test
    public void testMigrateBaseKeySuccessPartnerAppIdWithEmptyAlias() {
        KeyMigrateBaseKeyRequestDto requestDto = new KeyMigrateBaseKeyRequestDto();
        requestDto.setApplicationId(KeyMigratorConstants.PARTNER_APPID);
        requestDto.setReferenceId("REF_123");
        requestDto.setEncryptedKeyData("encrypted-data");
        requestDto.setCertificateData("cert-data");
        requestDto.setNotBefore(LocalDateTime.now());
        requestDto.setNotAfter(LocalDateTime.now().plusDays(1));

        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        keyAliasMap.put("currentKeyAlias", Collections.emptyList());

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        when(keymanagerUtil.convertToCertificate(anyString())).thenReturn(mockCertificate);
        when(cryptomanagerUtil.getCertificateThumbprintInHex(any(X509Certificate.class))).thenReturn("thumbprint");
        when(keyAliasRepository.findByApplicationIdAndReferenceIdAndCertThumbprint(anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());
        when(keymanagerUtil.getUniqueIdentifier(anyString())).thenReturn("unique-id");

        KeyMigrateBaseKeyResponseDto response = keyMigratorService.migrateBaseKey(requestDto);

        assertNotNull(response);
        assertEquals(KeyMigratorConstants.MIGRAION_SUCCESS, response.getStatus());
        verify(dbHelper, times(1)).storeKeyInDBStore(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    public void testMigrateBaseKeySuccessPartnerAppIdWithExistingAlias() {
        KeyMigrateBaseKeyRequestDto requestDto = new KeyMigrateBaseKeyRequestDto();
        requestDto.setApplicationId(KeyMigratorConstants.PARTNER_APPID);
        requestDto.setReferenceId("REF_123");
        requestDto.setEncryptedKeyData("encrypted-data");
        requestDto.setCertificateData("cert-data");
        requestDto.setNotBefore(LocalDateTime.now());
        requestDto.setNotAfter(LocalDateTime.now().plusDays(1));

        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias("master-key-alias");
        keyAliasMap.put("currentKeyAlias", Collections.singletonList(keyAlias));

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        when(keymanagerUtil.convertToCertificate(anyString())).thenReturn(mockCertificate);
        when(cryptomanagerUtil.getCertificateThumbprintInHex(any(X509Certificate.class))).thenReturn("thumbprint");
        when(keyAliasRepository.findByApplicationIdAndReferenceIdAndCertThumbprint(anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());
        when(keymanagerUtil.getUniqueIdentifier(anyString())).thenReturn("unique-id");

        KeyMigrateBaseKeyResponseDto response = keyMigratorService.migrateBaseKey(requestDto);

        assertNotNull(response);
        assertEquals(KeyMigratorConstants.MIGRAION_SUCCESS, response.getStatus());
        verify(dbHelper, times(1)).storeKeyInDBStore(anyString(), eq("master-key-alias"), anyString(), anyString());
    }

    @Test(expected = NoUniqueAliasException.class)
    public void testMigrateBaseKeyNoUniqueAlias() {
        KeyMigrateBaseKeyRequestDto requestDto = new KeyMigrateBaseKeyRequestDto();
        requestDto.setApplicationId("REGISTRATION");

        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        keyAliasMap.put("currentKeyAlias", Collections.emptyList());

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);

        keyMigratorService.migrateBaseKey(requestDto);
    }

    @Test
    public void testMigrateBaseKeyAlreadyExists() {
        KeyMigrateBaseKeyRequestDto requestDto = new KeyMigrateBaseKeyRequestDto();
        requestDto.setApplicationId("REGISTRATION");
        requestDto.setReferenceId("REF_123");
        requestDto.setCertificateData("cert-data");
        requestDto.setNotBefore(LocalDateTime.now());
        requestDto.setNotAfter(LocalDateTime.now().plusDays(1));

        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias("master-key-alias");
        keyAliasMap.put("currentKeyAlias", Collections.singletonList(keyAlias));

        KeyAlias existingKeyAlias = new KeyAlias();

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        when(keymanagerUtil.convertToCertificate(anyString())).thenReturn(mockCertificate);
        when(cryptomanagerUtil.getCertificateThumbprintInHex(any(X509Certificate.class))).thenReturn("thumbprint");
        when(keyAliasRepository.findByApplicationIdAndReferenceIdAndCertThumbprint(anyString(), anyString(), anyString()))
                .thenReturn(Collections.singletonList(existingKeyAlias));

        KeyMigrateBaseKeyResponseDto response = keyMigratorService.migrateBaseKey(requestDto);

        assertNotNull(response);
        assertEquals(KeyMigratorConstants.MIGRAION_NOT_ALLOWED, response.getStatus());
        assertNotNull(response.getTimestamp());
        verify(dbHelper, times(0)).storeKeyInDBStore(anyString(), anyString(), anyString(), anyString());
    }

    // ==================== getZKTempCertificate Tests ====================

    @Test
    public void testGetZKTempCertificateNewKey() {
        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        keyAliasMap.put("keyAlias", Collections.emptyList());
        keyAliasMap.put("currentKeyAlias", Collections.emptyList());

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        when(keyStore.getCertificate(anyString())).thenReturn(mockCertificate);
        when(keymanagerUtil.getPEMFormatedData(any(X509Certificate.class))).thenReturn("cert-data");
        when(cryptomanagerUtil.getCertificateThumbprintInHex(any(X509Certificate.class))).thenReturn("thumbprint");
        when(keymanagerUtil.getUniqueIdentifier(anyString())).thenReturn("unique-id");
        when(keymanagerUtil.getCertificateParameters(anyString(), any(LocalDateTime.class), any(LocalDateTime.class)))
                .thenReturn(mockCertificateParameters);

        ZKKeyMigrateCertficateResponseDto response = keyMigratorService.getZKTempCertificate();

        assertNotNull(response);
        assertNotNull(response.getCertificate());
        assertNotNull(response.getTimestamp());
        verify(keyStore, times(1)).generateAndStoreAsymmetricKey(anyString(), any(), any());
        verify(dbHelper, times(1)).storeKeyInAlias(anyString(), any(LocalDateTime.class), anyString(),
                anyString(), any(LocalDateTime.class), anyString(), anyString());
    }

    @Test
    public void testGetZKTempCertificateExistingKey() {
        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias("existing-alias");
        keyAliasMap.put("keyAlias", Collections.emptyList());
        keyAliasMap.put("currentKeyAlias", Collections.singletonList(keyAlias));

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        when(keyStore.getCertificate(anyString())).thenReturn(mockCertificate);
        when(keymanagerUtil.getPEMFormatedData(any(X509Certificate.class))).thenReturn("cert-data");

        ZKKeyMigrateCertficateResponseDto response = keyMigratorService.getZKTempCertificate();

        assertNotNull(response);
        assertEquals("cert-data", response.getCertificate());
        assertNotNull(response.getTimestamp());
        verify(keyStore, times(0)).generateAndStoreAsymmetricKey(anyString(), any(), any());
    }

    @Test
    public void testGetZKTempCertificateExpiredKey() {
        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        KeyAlias expiredKeyAlias = new KeyAlias();
        expiredKeyAlias.setAlias("expired-alias");
        keyAliasMap.put("keyAlias", Collections.singletonList(expiredKeyAlias));
        keyAliasMap.put("currentKeyAlias", Collections.emptyList());

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);
        when(keyStore.getCertificate(anyString())).thenReturn(mockCertificate);
        when(keymanagerUtil.getPEMFormatedData(any(X509Certificate.class))).thenReturn("cert-data");
        when(cryptomanagerUtil.getCertificateThumbprintInHex(any(X509Certificate.class))).thenReturn("thumbprint");
        when(keymanagerUtil.getUniqueIdentifier(anyString())).thenReturn("unique-id");
        when(keymanagerUtil.getCertificateParameters(anyString(), any(LocalDateTime.class), any(LocalDateTime.class)))
                .thenReturn(mockCertificateParameters);

        ZKKeyMigrateCertficateResponseDto response = keyMigratorService.getZKTempCertificate();

        assertNotNull(response);
        verify(keyStore, times(1)).deleteKey("expired-alias");
        verify(keyStore, times(1)).generateAndStoreAsymmetricKey(anyString(), any(), any());
        verify(dbHelper, times(1)).storeKeyInAlias(anyString(), any(LocalDateTime.class), anyString(),
                anyString(), any(LocalDateTime.class), isNull(), isNull());
    }

    @Test(expected = NoUniqueAliasException.class)
    public void testGetZKTempCertificateMultipleCurrentKeys() {
        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        KeyAlias keyAlias1 = new KeyAlias();
        KeyAlias keyAlias2 = new KeyAlias();
        keyAliasMap.put("keyAlias", Collections.emptyList());
        keyAliasMap.put("currentKeyAlias", List.of(keyAlias1, keyAlias2));

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);

        keyMigratorService.getZKTempCertificate();
    }

    // ==================== migrateZKKeys Tests ====================

    @Test
    public void testMigrateZKKeysSuccess() throws Exception {
        ZKKeyMigrateRequestDto requestDto = new ZKKeyMigrateRequestDto();
        ZKKeyDataDto keyData = new ZKKeyDataDto();
        keyData.setKeyIndex(1);
        keyData.setEncryptedKeyData("ZW5jcnlwdGVkLWtleS1kYXRh");
        requestDto.setZkEncryptedDataList(Collections.singletonList(keyData));
        requestDto.setPurgeTempKeyFlag(false);

        Map<String, List<KeyAlias>> keyAliasMapTemp = new HashMap<>();
        KeyAlias tempKeyAlias = new KeyAlias();
        tempKeyAlias.setAlias("temp-alias");
        keyAliasMapTemp.put("currentKeyAlias", Collections.singletonList(tempKeyAlias));

        Map<String, List<KeyAlias>> keyAliasMapMaster = new HashMap<>();
        KeyAlias masterKeyAlias = new KeyAlias();
        masterKeyAlias.setAlias("master-alias");
        keyAliasMapMaster.put("currentKeyAlias", Collections.singletonList(masterKeyAlias));

        when(mockCertificate.getPublicKey()).thenReturn(keyPair.getPublic());
        PrivateKeyEntry privateKeyEntry = new PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{mockCertificate});
        // AES key must be 16, 24, or 32 bytes - using 16 bytes for AES-128 to match the 16-byte data
        SecretKey secretKey = new SecretKeySpec("1234567890123456".getBytes(), "AES"); // 16 bytes for AES-128

        when(dbHelper.getKeyAliases(eq(KeyMigratorConstants.ZK_TEMP_KEY_APP_ID), eq(KeyMigratorConstants.ZK_TEMP_KEY_REF_ID), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapTemp);
        when(dbHelper.getKeyAliases(eq("KERNEL"), eq("IDENTITY_CACHE"), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapMaster);
        when(keyStore.getAsymmetricKey(anyString())).thenReturn(privateKeyEntry);
        when(keyStore.getSymmetricKey(anyString())).thenReturn(secretKey);
        when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(PublicKey.class), any(byte[].class)))
                .thenReturn("1234567890123456".getBytes()); // 16 bytes for AES-128
        when(dataEncryptKeystoreRepository.findKeyById(anyInt())).thenReturn(null);

        ZKKeyMigrateResponseDto response = keyMigratorService.migrateZKKeys(requestDto);

        assertNotNull(response);
        assertNotNull(response.getZkEncryptedDataList());
        assertEquals(1, response.getZkEncryptedDataList().size());
        assertEquals(KeyMigratorConstants.MIGRAION_SUCCESS, response.getZkEncryptedDataList().get(0).getStatusMessage());
        assertEquals(1, response.getZkEncryptedDataList().get(0).getKeyIndex());
        verify(dataEncryptKeystoreRepository, times(1)).save(any(DataEncryptKeystore.class));
        verify(keyStore, times(0)).deleteKey(anyString());
    }

    @Test
    public void testMigrateZKKeysWithPurge() throws Exception {
        ZKKeyMigrateRequestDto requestDto = new ZKKeyMigrateRequestDto();
        ZKKeyDataDto keyData = new ZKKeyDataDto();
        keyData.setKeyIndex(1);
        keyData.setEncryptedKeyData("ZW5jcnlwdGVkLWtleS1kYXRh");
        requestDto.setZkEncryptedDataList(Collections.singletonList(keyData));
        requestDto.setPurgeTempKeyFlag(true);

        Map<String, List<KeyAlias>> keyAliasMapTemp = new HashMap<>();
        KeyAlias tempKeyAlias = new KeyAlias();
        tempKeyAlias.setAlias("temp-alias");
        keyAliasMapTemp.put("currentKeyAlias", Collections.singletonList(tempKeyAlias));

        Map<String, List<KeyAlias>> keyAliasMapMaster = new HashMap<>();
        KeyAlias masterKeyAlias = new KeyAlias();
        masterKeyAlias.setAlias("master-alias");
        keyAliasMapMaster.put("currentKeyAlias", Collections.singletonList(masterKeyAlias));

        when(mockCertificate.getPublicKey()).thenReturn(keyPair.getPublic());
        PrivateKeyEntry privateKeyEntry = new PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{mockCertificate});
        SecretKey secretKey = new SecretKeySpec("test-key-1234567890123456".getBytes(), "AES");

        when(dbHelper.getKeyAliases(eq(KeyMigratorConstants.ZK_TEMP_KEY_APP_ID), eq(KeyMigratorConstants.ZK_TEMP_KEY_REF_ID), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapTemp);
        when(dbHelper.getKeyAliases(eq("KERNEL"), eq("IDENTITY_CACHE"), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapMaster);
        when(keyStore.getAsymmetricKey(anyString())).thenReturn(privateKeyEntry);
        when(keyStore.getSymmetricKey(anyString())).thenReturn(secretKey);
        when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(PublicKey.class), any(byte[].class)))
                .thenReturn("decrypted-data-16bytes".getBytes());
        when(dataEncryptKeystoreRepository.findKeyById(anyInt())).thenReturn(null);

        ZKKeyMigrateResponseDto response = keyMigratorService.migrateZKKeys(requestDto);

        assertNotNull(response);
        verify(keyStore, times(1)).deleteKey("temp-alias");
        verify(dbHelper, times(1)).storeKeyInAlias(anyString(), any(LocalDateTime.class), anyString(),
                anyString(), any(LocalDateTime.class), isNull(), isNull());
    }


    @Test
    public void testMigrateZKKeysMultipleKeys() throws Exception {
        ZKKeyMigrateRequestDto requestDto = new ZKKeyMigrateRequestDto();
        List<ZKKeyDataDto> keyDataList = new ArrayList<>();

        ZKKeyDataDto keyData1 = new ZKKeyDataDto();
        keyData1.setKeyIndex(1);
        keyData1.setEncryptedKeyData("ZW5jcnlwdGVkLWtleS1kYXRh");
        keyDataList.add(keyData1);

        ZKKeyDataDto keyData2 = new ZKKeyDataDto();
        keyData2.setKeyIndex(2);
        keyData2.setEncryptedKeyData("ZW5jcnlwdGVkLWtleS1kYXRh");
        keyDataList.add(keyData2);

        requestDto.setZkEncryptedDataList(keyDataList);
        requestDto.setPurgeTempKeyFlag(false);

        Map<String, List<KeyAlias>> keyAliasMapTemp = new HashMap<>();
        KeyAlias tempKeyAlias = new KeyAlias();
        tempKeyAlias.setAlias("temp-alias");
        keyAliasMapTemp.put("currentKeyAlias", Collections.singletonList(tempKeyAlias));

        Map<String, List<KeyAlias>> keyAliasMapMaster = new HashMap<>();
        KeyAlias masterKeyAlias = new KeyAlias();
        masterKeyAlias.setAlias("master-alias");
        keyAliasMapMaster.put("currentKeyAlias", Collections.singletonList(masterKeyAlias));

        when(mockCertificate.getPublicKey()).thenReturn(keyPair.getPublic());
        PrivateKeyEntry privateKeyEntry = new PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{mockCertificate});
        SecretKey secretKey = new SecretKeySpec("test-key-1234567890123456".getBytes(), "AES");

        when(dbHelper.getKeyAliases(eq(KeyMigratorConstants.ZK_TEMP_KEY_APP_ID), eq(KeyMigratorConstants.ZK_TEMP_KEY_REF_ID), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapTemp);
        when(dbHelper.getKeyAliases(eq("KERNEL"), eq("IDENTITY_CACHE"), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapMaster);
        when(keyStore.getAsymmetricKey(anyString())).thenReturn(privateKeyEntry);
        when(keyStore.getSymmetricKey(anyString())).thenReturn(secretKey);
        when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(PublicKey.class), any(byte[].class)))
                .thenReturn("decrypted-data-16bytes".getBytes());
        when(dataEncryptKeystoreRepository.findKeyById(anyInt())).thenReturn(null);

        ZKKeyMigrateResponseDto response = keyMigratorService.migrateZKKeys(requestDto);

        assertNotNull(response);
        assertEquals(2, response.getZkEncryptedDataList().size());
        assertEquals("Error in Migration", response.getZkEncryptedDataList().get(1).getStatusMessage());
    }

    @Test
    public void testMigrateZKKeysKeyExists() throws Exception {
        ZKKeyMigrateRequestDto requestDto = new ZKKeyMigrateRequestDto();
        ZKKeyDataDto keyData = new ZKKeyDataDto();
        keyData.setKeyIndex(1);
        keyData.setEncryptedKeyData("ZW5jcnlwdGVkLWtleS1kYXRh");
        requestDto.setZkEncryptedDataList(Collections.singletonList(keyData));

        Map<String, List<KeyAlias>> keyAliasMapTemp = new HashMap<>();
        KeyAlias tempKeyAlias = new KeyAlias();
        tempKeyAlias.setAlias("temp-alias");
        keyAliasMapTemp.put("currentKeyAlias", Collections.singletonList(tempKeyAlias));

        Map<String, List<KeyAlias>> keyAliasMapMaster = new HashMap<>();
        KeyAlias masterKeyAlias = new KeyAlias();
        masterKeyAlias.setAlias("master-alias");
        keyAliasMapMaster.put("currentKeyAlias", Collections.singletonList(masterKeyAlias));

        when(mockCertificate.getPublicKey()).thenReturn(keyPair.getPublic());
        PrivateKeyEntry privateKeyEntry = new PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{mockCertificate});
        SecretKey secretKey = new SecretKeySpec("test-key-1234567890123456".getBytes(), "AES");

        when(dbHelper.getKeyAliases(eq(KeyMigratorConstants.ZK_TEMP_KEY_APP_ID), eq(KeyMigratorConstants.ZK_TEMP_KEY_REF_ID), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapTemp);
        when(dbHelper.getKeyAliases(eq("KERNEL"), eq("IDENTITY_CACHE"), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapMaster);
        when(keyStore.getAsymmetricKey(anyString())).thenReturn(privateKeyEntry);
        when(keyStore.getSymmetricKey(anyString())).thenReturn(secretKey);
        when(dataEncryptKeystoreRepository.findKeyById(anyInt())).thenReturn("existing-key-data");

        ZKKeyMigrateResponseDto response = keyMigratorService.migrateZKKeys(requestDto);

        assertNotNull(response);
        assertEquals(KeyMigratorConstants.MIGRAION_NOT_ALLOWED, response.getZkEncryptedDataList().get(0).getStatusMessage());
        verify(dataEncryptKeystoreRepository, times(0)).save(any(DataEncryptKeystore.class));
    }

    @Test
    public void testMigrateZKKeysEncryptionFailed() throws Exception {
        ZKKeyMigrateRequestDto requestDto = new ZKKeyMigrateRequestDto();
        ZKKeyDataDto keyData = new ZKKeyDataDto();
        keyData.setKeyIndex(1);
        keyData.setEncryptedKeyData("ZW5jcnlwdGVkLWtleS1kYXRh");
        requestDto.setZkEncryptedDataList(Collections.singletonList(keyData));

        Map<String, List<KeyAlias>> keyAliasMapTemp = new HashMap<>();
        KeyAlias tempKeyAlias = new KeyAlias();
        tempKeyAlias.setAlias("temp-alias");
        keyAliasMapTemp.put("currentKeyAlias", Collections.singletonList(tempKeyAlias));

        Map<String, List<KeyAlias>> keyAliasMapMaster = new HashMap<>();
        KeyAlias masterKeyAlias = new KeyAlias();
        masterKeyAlias.setAlias("master-alias");
        keyAliasMapMaster.put("currentKeyAlias", Collections.singletonList(masterKeyAlias));

        when(mockCertificate.getPublicKey()).thenReturn(keyPair.getPublic());
        PrivateKeyEntry privateKeyEntry = new PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{mockCertificate});
        SecretKey secretKey = new SecretKeySpec("test-key-1234567890123456".getBytes(), "AES");

        when(dbHelper.getKeyAliases(eq(KeyMigratorConstants.ZK_TEMP_KEY_APP_ID), eq(KeyMigratorConstants.ZK_TEMP_KEY_REF_ID), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapTemp);
        when(dbHelper.getKeyAliases(eq("KERNEL"), eq("IDENTITY_CACHE"), any(LocalDateTime.class)))
                .thenReturn(keyAliasMapMaster);
        when(keyStore.getAsymmetricKey(anyString())).thenReturn(privateKeyEntry);
        when(keyStore.getSymmetricKey(anyString())).thenReturn(secretKey);
        when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(PublicKey.class), any(byte[].class)))
                .thenThrow(new InvalidDataException("KER-CRY-001", "Decryption failed"));
        when(dataEncryptKeystoreRepository.findKeyById(anyInt())).thenReturn(null);

        ZKKeyMigrateResponseDto response = keyMigratorService.migrateZKKeys(requestDto);

        assertNotNull(response);
        assertEquals(KeyMigratorConstants.MIGRAION_FAILED, response.getZkEncryptedDataList().get(0).getStatusMessage());
        verify(dataEncryptKeystoreRepository, times(0)).save(any(DataEncryptKeystore.class));
    }

    // ==================== getKeyAlias Tests ====================

    @Test(expected = NoUniqueAliasException.class)
    public void testGetKeyAliasNoUniqueAlias() {
        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        keyAliasMap.put("currentKeyAlias", Collections.emptyList());

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);

        ReflectionTestUtils.invokeMethod(keyMigratorService, "getKeyAlias", "APP_ID", "REF_ID", LocalDateTime.now());
    }

    @Test(expected = NoUniqueAliasException.class)
    public void testGetKeyAliasMultipleAliases() {
        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        KeyAlias keyAlias1 = new KeyAlias();
        KeyAlias keyAlias2 = new KeyAlias();
        keyAliasMap.put("currentKeyAlias", List.of(keyAlias1, keyAlias2));

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);

        ReflectionTestUtils.invokeMethod(keyMigratorService, "getKeyAlias", "APP_ID", "REF_ID", LocalDateTime.now());
    }

    @Test
    public void testGetKeyAliasSuccess() {
        Map<String, List<KeyAlias>> keyAliasMap = new HashMap<>();
        KeyAlias keyAlias = new KeyAlias();
        keyAlias.setAlias("test-alias");
        keyAliasMap.put("currentKeyAlias", Collections.singletonList(keyAlias));

        when(dbHelper.getKeyAliases(anyString(), anyString(), any(LocalDateTime.class))).thenReturn(keyAliasMap);

        String result = (String) ReflectionTestUtils.invokeMethod(keyMigratorService, "getKeyAlias", "APP_ID", "REF_ID", LocalDateTime.now());

        assertEquals("test-alias", result);
    }

    // ==================== isValidKeyExists Tests ====================

    @Test
    public void testIsValidKeyExistsTrue() {
        KeyAlias existingKeyAlias = new KeyAlias();
        when(keyAliasRepository.findByApplicationIdAndReferenceIdAndCertThumbprint(anyString(), anyString(), anyString()))
                .thenReturn(Collections.singletonList(existingKeyAlias));

        boolean result = (Boolean) ReflectionTestUtils.invokeMethod(keyMigratorService, "isValidKeyExists", "APP_ID", "REF_ID", "thumbprint");

        assertEquals(true, result);
    }

    @Test
    public void testIsValidKeyExistsFalse() {
        when(keyAliasRepository.findByApplicationIdAndReferenceIdAndCertThumbprint(anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());

        boolean result = (Boolean) ReflectionTestUtils.invokeMethod(keyMigratorService, "isValidKeyExists", "APP_ID", "REF_ID", "thumbprint");

        assertEquals(false, result);
    }

    @Test
    public void testIsValidKeyExistsMultipleKeys() {
        KeyAlias existingKeyAlias1 = new KeyAlias();
        KeyAlias existingKeyAlias2 = new KeyAlias();
        when(keyAliasRepository.findByApplicationIdAndReferenceIdAndCertThumbprint(anyString(), anyString(), anyString()))
                .thenReturn(List.of(existingKeyAlias1, existingKeyAlias2));

        boolean result = (Boolean) ReflectionTestUtils.invokeMethod(keyMigratorService, "isValidKeyExists", "APP_ID", "REF_ID", "thumbprint");

        assertEquals(true, result);
    }

    // ==================== isKeyIndexExist Tests ====================

    @Test
    public void testIsKeyIndexExistTrue() {
        when(dataEncryptKeystoreRepository.findKeyById(anyInt())).thenReturn("existing-key-data");

        boolean result = (Boolean) ReflectionTestUtils.invokeMethod(keyMigratorService, "isKeyIndexExist", 1);

        assertEquals(true, result);
    }

    @Test
    public void testIsKeyIndexExistFalse() {
        when(dataEncryptKeystoreRepository.findKeyById(anyInt())).thenReturn(null);

        boolean result = (Boolean) ReflectionTestUtils.invokeMethod(keyMigratorService, "isKeyIndexExist", 1);

        assertEquals(false, result);
    }

    // ==================== insertKey Tests ====================

    @Test
    public void testInsertKey() {
        ReflectionTestUtils.invokeMethod(keyMigratorService, "insertKey", 1, "secret-data", "ACTIVE");

        verify(dataEncryptKeystoreRepository, times(1)).save(any(DataEncryptKeystore.class));
    }

    // ==================== encryptRandomKey Tests ====================

    @Test
    public void testEncryptRandomKeySuccess() throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        // AES key must be 16, 24, or 32 bytes - using 16 bytes for AES-128
        SecretKey secretKey = new SecretKeySpec("1234567890123456".getBytes(), "AES"); // 16 bytes
        byte[] encryptedData = "encrypted-data".getBytes();
        // Decrypted data must be properly sized for AES encryption (multiple of 16 bytes for AES/ECB/NoPadding)
        byte[] decryptedData = "1234567890123456".getBytes(); // 16 bytes

        when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(PublicKey.class), any(byte[].class)))
                .thenReturn(decryptedData);

        byte[] result = (byte[]) ReflectionTestUtils.invokeMethod(keyMigratorService, "encryptRandomKey",
                encryptedData, secretKey, privateKey, publicKey);

        assertNotNull(result);
    }

    @Test
    public void testEncryptRandomKeyFailureInvalidDataException() throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        SecretKey secretKey = new SecretKeySpec("test-key-1234567890123456".getBytes(), "AES");
        byte[] encryptedData = "encrypted-data".getBytes();

        when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(PublicKey.class), any(byte[].class)))
                .thenThrow(new InvalidDataException("KER-CRY-001", "Decryption failed"));

        byte[] result = (byte[]) ReflectionTestUtils.invokeMethod(keyMigratorService, "encryptRandomKey",
                encryptedData, secretKey, privateKey, publicKey);

        assertNull(result);
    }

    @Test
    public void testEncryptRandomKeyFailureCoreInvalidKeyException() throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        SecretKey secretKey = new SecretKeySpec("test-key-1234567890123456".getBytes(), "AES");
        byte[] encryptedData = "encrypted-data".getBytes();

        when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(PublicKey.class), any(byte[].class)))
                .thenThrow(new InvalidKeyException("KER-CRY-002", "Invalid key"));

        byte[] result = (byte[]) ReflectionTestUtils.invokeMethod(keyMigratorService, "encryptRandomKey",
                encryptedData, secretKey, privateKey, publicKey);

        assertNull(result);
    }

    @Test
    public void testEncryptRandomKeyFailureNoSuchAlgorithmException() throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        SecretKey secretKey = new SecretKeySpec("test-key-1234567890123456".getBytes(), "AES");
        byte[] encryptedData = "encrypted-data".getBytes();
        byte[] decryptedData = "decrypted-data-16bytes".getBytes();

        when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(PublicKey.class), any(byte[].class)))
                .thenReturn(decryptedData);

        ReflectionTestUtils.setField(keyMigratorService, "aesECBTransformation", "INVALID/ALGORITHM");

        byte[] result = (byte[]) ReflectionTestUtils.invokeMethod(keyMigratorService, "encryptRandomKey",
                encryptedData, secretKey, privateKey, publicKey);

        assertNull(result);

        // Restore original transformation
        ReflectionTestUtils.setField(keyMigratorService, "aesECBTransformation", "AES/ECB/NoPadding");
    }

    @Test
    public void testEncryptRandomKeyFailureNoSuchPaddingException() throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        SecretKey secretKey = new SecretKeySpec("test-key-1234567890123456".getBytes(), "AES");
        byte[] encryptedData = "encrypted-data".getBytes();
        byte[] decryptedData = "decrypted-data-16bytes".getBytes();

        when(cryptoCore.asymmetricDecrypt(any(PrivateKey.class), any(PublicKey.class), any(byte[].class)))
                .thenReturn(decryptedData);

        ReflectionTestUtils.setField(keyMigratorService, "aesECBTransformation", "AES/INVALID/NoPadding");

        byte[] result = (byte[]) ReflectionTestUtils.invokeMethod(keyMigratorService, "encryptRandomKey",
                encryptedData, secretKey, privateKey, publicKey);

        assertNull(result);

        // Restore original transformation
        ReflectionTestUtils.setField(keyMigratorService, "aesECBTransformation", "AES/ECB/NoPadding");
    }
}