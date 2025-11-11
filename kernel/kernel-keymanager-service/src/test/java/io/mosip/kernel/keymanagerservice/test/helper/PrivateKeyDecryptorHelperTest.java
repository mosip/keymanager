package io.mosip.kernel.keymanagerservice.test.helper;

import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.dto.CSRGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.entity.KeyStore;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.helper.PrivateKeyDecryptorHelper;
import io.mosip.kernel.keymanagerservice.repository.KeyAliasRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class PrivateKeyDecryptorHelperTest {

    @Autowired
    private PrivateKeyDecryptorHelper decryptorHelper;

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeyAliasRepository keyAliasRepository;

    @Before
    public void setUp() {
        KeyPairGenerateRequestDto keyPairGenRequestDto = new KeyPairGenerateRequestDto();
        keyPairGenRequestDto.setApplicationId("ROOT");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);

        keyPairGenRequestDto.setApplicationId("TEST");
        keyPairGenRequestDto.setReferenceId("");
        keymanagerService.generateMasterKey("CSR", keyPairGenRequestDto);
    }

    @After
    public void tearDown() {
        keyAliasRepository.deleteAll();
    }

    @Test
    public void testGetDBKeyStoreData() {
        CSRGenerateRequestDto csrGenerateRequestDto = new CSRGenerateRequestDto();
        csrGenerateRequestDto.setApplicationId("TEST");
        csrGenerateRequestDto.setReferenceId("test");
        keymanagerService.generateCSR(csrGenerateRequestDto);

        List<KeyAlias> certDetails = keyAliasRepository.findByApplicationIdAndReferenceId("TEST", "test");
        String certThumbprint = certDetails.get(0).getCertThumbprint();
        KeyStore result = decryptorHelper.getDBKeyStoreData(certThumbprint, "TEST", "test");

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getAlias());
    }

    @Test
    public void testGetKeyObjectsOtherDomainKey() {
        KeyStore otherDomainKeyStore = new KeyStore();
        String alias = "TEST_ALIAS";
        otherDomainKeyStore.setAlias(alias);
        otherDomainKeyStore.setMasterAlias(alias);
        otherDomainKeyStore.setPrivateKey("somePrivateKey");
        otherDomainKeyStore.setCertificateData("someCertData");

        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            decryptorHelper.getKeyObjects(otherDomainKeyStore, false);
        });
        Assert.assertEquals(KeymanagerErrorConstant.DECRYPTION_NOT_ALLOWED.getErrorCode(),
                exception.getErrorCode());
    }

    @Test
    public void testGetKeyObjectsWithNAPrivateKey() {
        KeyStore naKeyStore = new KeyStore();
        naKeyStore.setAlias("TEST_ALIAS");
        naKeyStore.setMasterAlias("MASTER_ALIAS");
        naKeyStore.setPrivateKey("NA");
        naKeyStore.setCertificateData("someCertData");

        KeymanagerServiceException exception = assertThrows(KeymanagerServiceException.class, () -> {
            decryptorHelper.getKeyObjects(naKeyStore, false);
        });
        Assert.assertEquals(KeymanagerErrorConstant.DECRYPTION_NOT_ALLOWED.getErrorCode(),
                exception.getErrorCode());
    }
}
