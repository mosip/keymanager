package io.mosip.kernel.signature.service;

import java.security.PrivateKey;

public interface SignatureProvider {
    
    /**
	 * perform Signature for the inputed Data using the provided key.
	 *
	 * 
	 * @return the String - signed data in Base64URLEncode
	 */
	public String sign(PrivateKey privateKey, byte[] signData, String providerName);
}
