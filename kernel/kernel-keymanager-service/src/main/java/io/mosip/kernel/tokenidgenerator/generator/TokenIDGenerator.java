package io.mosip.kernel.tokenidgenerator.generator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.HMACUtils2;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


@Component
public class TokenIDGenerator {

	private static final Logger LOGGER = KeymanagerLogger.getLogger(TokenIDGenerator.class);

	@Value("${mosip.kernel.tokenid.uin.salt}")
	private String uinSalt;

	@Value("${mosip.kernel.tokenid.length}")
	private int tokenIDLength;

	@Value("${mosip.kernel.tokenid.partnercode.salt}")
	private String partnerCodeSalt;

	public String generateTokenID(String uin, String partnerCode) {
		try {
			String uinHash = HMACUtils2.digestAsPlainText((uin + uinSalt).getBytes(StandardCharsets.UTF_8));
			String hash = HMACUtils2.digestAsPlainText((partnerCodeSalt + partnerCode + uinHash).getBytes(StandardCharsets.UTF_8));
			return new BigInteger(hash.getBytes()).toString().substring(0, tokenIDLength);
		} catch (java.security.NoSuchAlgorithmException e) {
			LOGGER.error("Error generating token ID: No such algorithm found", e);
			return null;
		}
	}

}
