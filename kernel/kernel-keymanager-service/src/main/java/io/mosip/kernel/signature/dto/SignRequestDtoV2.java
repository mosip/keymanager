package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 
 * @author Mahammed Taheer
 * @since 1.2.0-SNAPSHOT
 *
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignRequestDtoV2 {

    @NotBlank
    @ApiModelProperty(notes = "Base64 encoded JSON Data to sign", example = "ewogICAiYW55S2V5IjogIlRlc3QgSnNvbiIKfQ", required = true)
	private String dataToSign;

	/**
	 * Application id of decrypting module
	 */
	@ApiModelProperty(notes = "Application id to be used for signing", example = "KERNEL", required = false)
	private String applicationId;

	/**
	 * Refrence Id
	 */
	@ApiModelProperty(notes = "Refrence Id", example = "SIGN", required = false)
	private String referenceId;


	@ApiModelProperty(notes = "Encoding format of the signature: base64url, base58btc")
	private String responseEncodingFormat;

	/**
	 * Algorithm to use for data signing. Current supported Algorithm [PS256,...]
	 */
	@ApiModelProperty(notes = "Algorithm to use for data signing. Current supported Algorithm PS256.", required = false)
	// get algo names from rfc7518, except `none`
	private String signAlgorithm;

}
