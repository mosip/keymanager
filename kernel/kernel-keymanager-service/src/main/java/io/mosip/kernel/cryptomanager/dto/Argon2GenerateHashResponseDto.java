/*
 * 
 * 
 * 
 * 
 */
package io.mosip.kernel.cryptomanager.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * To generate Argon2 Hash Response model
 * 
 * @author Mahammed Taheer
 *
 * @since 1.2.1
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representing to generate Argon2 Hash Response")
public class Argon2GenerateHashResponseDto {

	/**
	 *  Argon2 generated Hash value
	 */
	@ApiModelProperty(notes = "generate Argon2 Hash")
	private String hashValue;

	/**
	 *  Salt value used in hash generation
	 */
	@ApiModelProperty(notes = "Salt value used in Argon2 Hash")
	private String salt;
}
