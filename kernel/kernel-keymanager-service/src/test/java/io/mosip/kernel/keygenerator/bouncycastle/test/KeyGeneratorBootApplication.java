package io.mosip.kernel.keygenerator.bouncycastle.test;

import io.mosip.kernel.TestAutoConfigurationExclusions;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@TestAutoConfigurationExclusions
@SpringBootApplication
@ComponentScan({ "io.mosip.kernel.keygenerator.*" })
public class KeyGeneratorBootApplication {
	public static void main(String[] args) {
		SpringApplication.run(KeyGeneratorBootApplication.class, args);

	}

}
