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
 * To generate Argon2 Hash Request model
 * 
 * @author Mahammed Taheer
 *
 * @since 1.2.1
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representing a to generate Argon2 Hash Request")
public class Argon2GenerateHashRequestDto {

	/**
	 * Input data for hash generation
	 */
	@ApiModelProperty(notes = "Input data for hash generation.", example = "SOME-BASE64-ENCODED-STRING", required = true)
	@NotBlank(message = CryptomanagerConstant.INVALID_REQUEST)
	private String inputData;
	
	/**
	 * Salt to be included in the hash generation (Optional)
	 */
	@ApiModelProperty(notes = "Salt value to be included in hash generation", example = "RANDOM-BYTES-DATA")
	private String salt;
}
