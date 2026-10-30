package io.mosip.kernel.keymanagerservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Key Manager Application
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
@EnableAutoConfiguration(excludeName = {
		"io.mosip.kernel.idgenerator.vid.impl.VidGeneratorImpl",
		"io.mosip.kernel.idgenerator.vid.util.VidFilterUtils",
		"io.mosip.kernel.idgenerator.tokenid.impl.TokenIdGeneratorImpl",
		"io.mosip.kernel.idgenerator.machineid.impl.MachineIdGeneratorImpl",
		"io.mosip.kernel.idgenerator.regcenterid.impl.RegistrationCenterIdGeneratorImpl",
		"io.mosip.kernel.idgenerator.mispid.impl.MispIdGeneratorImpl",
		"io.mosip.kernel.licensekeygenerator.misp.impl.MISPLicenseKeyGeneratorImpl",
		"io.mosip.kernel.licensekeygenerator.misp.util.MISPLicenseKeyGeneratorUtil",
		"io.mosip.kernel.idgenerator.rid.impl.RidGeneratorImpl",
		"io.mosip.kernel.idvalidator.prid.impl.PridValidatorImpl",
		"io.mosip.kernel.idvalidator.rid.impl.RidValidatorImpl",
		"io.mosip.kernel.idvalidator.uin.impl.UinValidatorImpl",
		"io.mosip.kernel.idvalidator.vid.impl.VidValidatorImpl",
		"io.mosip.kernel.idvalidator.mispid.impl.MispIdValidatorImpl",
		"io.mosip.kernel.templatemanager.velocity.builder.TemplateManagerBuilderImpl",
		"io.mosip.kernel.qrcode.generator.zxing.QrcodeGeneratorImpl",
		"io.mosip.kernel.transliteration.icu4j.impl.TransliterationImpl",
		"io.mosip.kernel.applicanttype.api.impl.ApplicantTypeImpl",
		"io.mosip.kernel.idobjectvalidator.config.IdObjectValidatorConfig",
		"io.mosip.kernel.websub.api.config.IntentVerificationConfig",
		"io.mosip.kernel.websub.api.config.WebSubClientConfig",
		"io.mosip.kernel.websub.api.config.publisher.WebSubPublisherClientConfig",
		"io.mosip.kernel.websub.api.config.publisher.RestTemplateHelper"
})
@SpringBootApplication(scanBasePackages = { "io.mosip.kernel.cryptomanager.*", "io.mosip.kernel.keymanagerservice.*",
		"${mosip.auth.adapter.impl.basepackage}", "io.mosip.kernel.signature.*", "io.mosip.kernel.tokenidgenerator.*",
		"io.mosip.kernel.lkeymanager.*", "io.mosip.kernel.keymanager.*", "io.mosip.kernel.keygenerator.*",
		"io.mosip.kernel.crypto.*", "io.mosip.kernel.zkcryptoservice.*", "io.mosip.kernel.partnercertservice.*",
		"io.mosip.kernel.clientcrypto.*", "io.mosip.kernel.core.logger.config", "io.mosip.kernel.keymigrate.*",
	    "io.mosip.kernel.pdfgenerator.*"})
public class KeymanagerBootApplication {

	/**
	 * Main method to run spring boot application
	 * 
	 * @param args args
	 */

	public static void main(String[] args) {

		SpringApplication.run(KeymanagerBootApplication.class, args);
	}
}
