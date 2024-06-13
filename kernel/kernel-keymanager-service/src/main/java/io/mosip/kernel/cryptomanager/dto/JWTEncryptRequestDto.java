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
 * Crypto-Manager-JWT-Encrypt Request model
 * 
 * @author Mahammed Taheer
 *
 * @since 1.2.1
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representing a Crypto-Manager-JWT Encrypt Request")
public class JWTEncryptRequestDto {
	/**
	 * Application id of component
	 */
	@ApiModelProperty(notes = "Application id of component", example = "REGISTRATION", required = true)
	private String applicationId;
	
	/**
	 * Refrence Id
	 */
	@ApiModelProperty(notes = "Refrence Id", example = "REF01")
	private String referenceId;
	
	/**
	 * Data in BASE64 encoding to encrypt/decrypt
	 */
	@ApiModelProperty(notes = "Data in BASE64 encoding to encrypt/decrypt", required = true)
	@NotBlank(message = CryptomanagerConstant.INVALID_REQUEST)
	private String data;
	
	/**
	* flag to enable Data Compression, default to false. 
	*/
	@ApiModelProperty(notes = "flag to enable data compression before encryption.", example = "false", required = false)
	private Boolean enableDefCompression;

	/**
	 * Flag to include certificate in JWT Encryption Header
	 */
	@ApiModelProperty(notes = "Flag to include certificate in JWT Encryption Header.", example = "false", required = false)
	private Boolean includeCertificate;

	/**
	 * Flag to include certificate hash in JWT Encryption Header
	 */
	@ApiModelProperty(notes = "Flag to include certificate hash(sha256) in JWT Encryption Header.", example = "false", required = false)
	private Boolean includeCertHash;

	/**
	 * JWK Set URL to include in JWT Encryption Header
	 */
	@ApiModelProperty(notes = "JWK Set URL to include in JWT Encryption Header.", example = "false", required = false)
	private String jwkSetUrl;

	/**
	 * Certificate to be used for JWT Encryption
	 */
	@ApiModelProperty(notes = "Certificate to be used for JWT Encryption.", example = "false", required = false)
	private String x509Certificate;

	@Override
	public String toString() {
		return "JWTEncryptRequestDto [applicationId=" + applicationId + ", referenceId=" + referenceId
				+ ", enableCompression=" + enableDefCompression + "]";
	}
}
