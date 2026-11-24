package io.mosip.kernel.cryptomanager.test.integration;

import org.springframework.test.context.TestPropertySource;

/** Key rotation / expiry decryption with EC secp256k1 keys. */
@TestPropertySource(properties = {"mosip.kernel.keygenerator.asymmetric-algorithm-name=EC", "mosip.kernel.keygenerator.ecc-curve-name=SECP256K1"})
public class EcSecp256k1KeyRotationDecryptTest extends AbstractKeyRotationDecryptTest {

	@Override
	protected String expectedEncryptionKeyAlgorithm() { return "EC"; }

	@Override
	protected String expectedCurveName() { return "SECP256K1"; }

	@Override
	protected String hsmEncryptionRefId() { return ""; }
}
