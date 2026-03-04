package io.mosip.kernel.migratealgorithm;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.migratealgorithm.impl.ComponentKeysAlgorithmMigrator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication(scanBasePackages = { "io.mosip.kernel.keygenerator.*", "io.mosip.kernel.keymanagerservice.*",
        "io.mosip.kernel.keymanager.*", "io.mosip.kernel.crypto.*", "io.mosip.kernel.cryptomanager.*",
        "io.mosip.kernel.migratealgorithm.*" })

public class MigrateKeysAlgorithmApplication implements CommandLineRunner {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(MigrateKeysAlgorithmApplication.class);

    @Autowired
    ComponentKeysAlgorithmMigrator algorithmMigrator;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    public static void main(String[] args) {
        ConfigurableApplicationContext run = SpringApplication.run(MigrateKeysAlgorithmApplication.class, args);
        SpringApplication.exit(run);
    }

    @Override
    public void run(String... args) throws Exception {
        LOGGER.info("Algorithm Migration started.......");
        algorithmMigrator.migrateAlgorithm();
        LOGGER.info("Algorithm Migration Completed.......");
    }
}
