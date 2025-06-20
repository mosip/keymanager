package io.mosip.kernel.cryptomanager.test.service;

import io.mosip.kernel.clientcrypto.test.ClientCryptoTestBootApplication;
import io.mosip.kernel.cryptomanager.service.impl.EcCryptoOperationImpl;
import io.mosip.kernel.keymanagerservice.test.KeymanagerTestBootApplication;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest(classes = { KeymanagerTestBootApplication.class })
@RunWith(SpringRunner.class)
public class EcCryptoOperationTest {

    @Autowired
    private EcCryptoOperationImpl service;

    private final String privateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCC6m5SEHQms8YoFUfABl3P918oNQwIJeGDukOeNV6e8Hw==";
    public final String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvMnarFay31WXcB/xsxBEOccl6+qJ88ctrzF9Rj9VqrLXk0Camh5x04cuA2cI9V8UWx9EhvPV7Wg4oS2aGs29Kg==";

    @Test
    public void testAsymmetricEcEncrypt() {

    }
}
