package io.mosip.kernel.crypto.jce.test;

import io.mosip.kernel.TestAutoConfigurationExclusions;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@TestAutoConfigurationExclusions
@SpringBootApplication
@ComponentScan({ "io.mosip.kernel.crypto.jce.*" })
public class CryptoJceBootApplication {
	public static void main(String[] args) {
		SpringApplication.run(CryptoJceBootApplication.class, args);

	}

}
