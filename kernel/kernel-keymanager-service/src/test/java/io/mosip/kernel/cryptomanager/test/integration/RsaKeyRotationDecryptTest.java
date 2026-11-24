package io.mosip.kernel.cryptomanager.test.integration;

import org.springframework.test.context.TestPropertySource;

/** Key rotation / expiry decryption with RSA keys (baseline, session-key path). */
@TestPropertySource(properties = {"mosip.kernel.keygenerator.asymmetric-algorithm-name=RSA"})
public class RsaKeyRotationDecryptTest extends AbstractKeyRotationDecryptTest {

	@Override
	protected String expectedEncryptionKeyAlgorithm() { return "RSA"; }

	@Override
	protected String expectedCurveName() { return null; }

	@Override
	protected String hsmEncryptionRefId() { return null; }
}
