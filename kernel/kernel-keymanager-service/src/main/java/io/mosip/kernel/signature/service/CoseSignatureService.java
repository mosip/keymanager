package io.mosip.kernel.signature.service;

import io.mosip.kernel.signature.dto.CWTSignRequestDto;
import io.mosip.kernel.signature.dto.CWTVerifyRequestDto;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.dto.CoseSignResponseDto;
import io.mosip.kernel.signature.dto.CoseSignVerifyRequestDto;
import io.mosip.kernel.signature.dto.CoseSignVerifyResponseDto;

public interface CoseSignatureService {

    /**
     * COSE Sign
     *
     * @param coseSignRequestDto the COSESignRequestDto
     * @return the COSESignResponseDto
     */
    public CoseSignResponseDto coseSign1(CoseSignRequestDto coseSignRequestDto);

    /**
     * COSE Verify
     *
     * @param coseSignVerifyRequestDto the COSESignVerifyRequestDto
     * @return the COSESignVerifyResponseDto
     */
    public CoseSignVerifyResponseDto coseVerify1(CoseSignVerifyRequestDto coseSignVerifyRequestDto);

    /**
     * CWT Sign
     *
     * @param cwtSignRequestDto the CoseSignRequestDto
     * @return the CoseSignResponseDto
     */
    public CoseSignResponseDto cwtSign(CWTSignRequestDto cwtSignRequestDto);

    /**
     * CWT Verify
     *
     * @param coseSignVerifyRequestDto the CoseSignVerifyRequestDto
     * @return the CoseSignVerifyResponseDto
     */
    public CoseSignVerifyResponseDto cwtVerify(CWTVerifyRequestDto coseSignVerifyRequestDto);
}
