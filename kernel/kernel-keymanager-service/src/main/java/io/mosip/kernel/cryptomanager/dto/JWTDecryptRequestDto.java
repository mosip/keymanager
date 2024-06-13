/*
 * 
 * 
 * 
 * 
 */
package io.mosip.kernel.cryptomanager.dto;

import jakarta.validation.constraints.NotBlank;

import io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Crypto-Manager-JWT-Decrypt Request model
 * 
 * @author Mahammed Taheer
 *
 * @since 1.2.1
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representing a Crypto-Manager-JWT Decrypt Request")
public class JWTDecryptRequestDto {
	/**
	 * Application id of component
	 */
	@ApiModelProperty(notes = "Application id of component", example = "REGISTRATION", required = true)
	@NotBlank(message = CryptomanagerConstant.INVALID_REQUEST)
	private String applicationId;
	
	/**
	 * Refrence Id
	 */
	@ApiModelProperty(notes = "Refrence Id", example = "REF01")
	@NotBlank(message = CryptomanagerConstant.INVALID_REQUEST)
	private String referenceId;
	
	/**
	 * Data in BASE64 encoding to encrypt/decrypt
	 */
	@ApiModelProperty(notes = "Data in BASE64 encoding to encrypt/decrypt", required = true)
	@NotBlank(message = CryptomanagerConstant.INVALID_REQUEST)
	private String encData;
	
	@Override
	public String toString() {
		return "JWTDecryptRequestDto [applicationId=" + applicationId + ", referenceId=" + referenceId + "]";
	}
}
