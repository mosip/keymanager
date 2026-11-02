package io.mosip.kernel.clientcrypto.test;

import io.mosip.kernel.TestAutoConfigurationExclusions;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@TestAutoConfigurationExclusions
@SpringBootApplication(scanBasePackages = { "io.mosip.kernel.clientcrypto.*", "io.mosip.kernel.crypto.jce.*"})
public class ClientCryptoTestBootApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClientCryptoTestBootApplication.class, args);
    }
}
