/*
 * 
 * 
 * 
 * 
 */
package io.mosip.kernel.cryptomanager.dto;

import java.time.LocalDateTime;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Crypto-Manager-JWT-Encrypt/Decrypt Response model
 * 
 * @author Mahammed Taheer
 *
 * @since 1.2.1
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representing a Crypto-Manager-JWT Encrypt/Decrypt Response")
public class JWTCipherResponseDto {
	
	/**
	 * Data Encrypted/Decrypted in BASE64 encoding
	 */
	@ApiModelProperty(notes = "Data encrypted/decrypted in BASE64 encoding")
	private String data;

	/**
	 * response time.
	 */
	@ApiModelProperty(notes = "Response time")
	private LocalDateTime timestamp;
}
