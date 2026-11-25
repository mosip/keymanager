package io.mosip.kernel.cryptomanager.test.integration;

import org.springframework.test.context.TestPropertySource;

/** Key rotation / expiry decryption with Ed25519 master (signing) + X25519 encryption keys. */
@TestPropertySource(properties = {"mosip.kernel.keygenerator.asymmetric-algorithm-name=EC", "mosip.kernel.keygenerator.ecc-curve-name=Ed25519"})
public class X25519KeyRotationDecryptTest extends AbstractKeyRotationDecryptTest {

	@Override
	protected String expectedEncryptionKeyAlgorithm() { return "X25519"; }

	@Override
	protected String expectedCurveName() { return "X25519"; }

	@Override
	protected String hsmEncryptionRefId() { return null; } // X25519_ENC_KEY is internal (wraps base keys), never exposed for direct encryption
}
