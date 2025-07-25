package io.mosip.kernel.signature.service;

import io.mosip.kernel.signature.dto.*;

public interface SignatureServicev2 extends SignatureService {
<<<<<<< HEAD
	/**
	 * JSON Web Signature(JWS) for the input data using input algorithm
	 *
	 * @param signatureReq
	 * @return the {@link SignResponseDto}
	 */
	public SignResponseDto signv2(SignRequestDtoV2 signatureReq);

}
=======
    /**
     * Signature for the input data using input algorithm
     *
     * @param signatureReq
     * @return the {@link SignResponseDto}
     */
    public SignResponseDto signv2(SignRequestDtoV2 signatureReq);

    /**
     * Signature for the input raw data using input algorithm
     *
     * @param signatureReq
     * @return the {@link SignResponseDto}
     */
    public SignResponseDtoV2 rawSign(SignRequestDtoV2 signatureReq);

}
>>>>>>> e5bf7d810fee4dd19d77bfac3f22f9eb49bb4b17
