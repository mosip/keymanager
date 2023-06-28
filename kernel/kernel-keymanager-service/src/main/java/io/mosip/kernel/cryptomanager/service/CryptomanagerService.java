/*
 * 
 * 
 * 
 * 
 */
package io.mosip.kernel.cryptomanager.service;

import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerResponseDto;
import io.mosip.kernel.cryptomanager.dto.JWTEncryptRequestDto;
import io.mosip.kernel.cryptomanager.dto.JWTCipherResponseDto;
import io.mosip.kernel.cryptomanager.dto.JWTDecryptRequestDto;

/**
 * This interface provides the methods which can be used for Encryption and
 * Decryption.
 *
 * @author Urvil Joshi
 * @author Srinivasan
 * @since 1.0.0
 */
public interface CryptomanagerService {

	/**
	 * Encrypt the data requested with metadata.
	 *
	 * @param cryptoRequestDto {@link CryptomanagerRequestDto} instance
	 * @return encrypted data
	 */
	public CryptomanagerResponseDto encrypt(CryptomanagerRequestDto cryptoRequestDto);

	/**
	 * Decrypt data requested with metadata.
	 *
	 * @param cryptoRequestDto {@link CryptomanagerRequestDto} instance
	 * @return decrypted data
	 */
	public CryptomanagerResponseDto decrypt(CryptomanagerRequestDto cryptoRequestDto);

	/**
	 * Encrypt the data requested with metadata.
	 *
	 * @param requestDto {@link CryptoWithPinRequestDto} instance
	 * @return encrypted data
	 */
	public CryptoWithPinResponseDto encryptWithPin(CryptoWithPinRequestDto requestDto);

	/**
	 * Decrypt data requested with metadata.
	 *
	 * @param requestDto {@link CryptoWithPinRequestDto} instance
	 * @return decrypted data
	 */
	public CryptoWithPinResponseDto decryptWithPin(CryptoWithPinRequestDto requestDto);

	/**
	 * Performs JWE Encryption for the input data.
	 *
	 * @param jwtCipherRequestDto {@link JWTEncryptRequestDto} instance
	 * @return encrypted data
	 */
	public JWTCipherResponseDto jwtEncrypt(JWTEncryptRequestDto jwtCipherRequestDto);

	/**
	 * Performs JWE Decryption for the input encrypted data.
	 *
	 * @param jwtCipherRequestDto {@link JWTEncryptRequestDto} instance
	 * @return decrypted data (actual data)
	 */
	public JWTCipherResponseDto jwtDecrypt(JWTDecryptRequestDto jwtCipherRequestDto);
}
