package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for verifying CWT signed data.
 *
 * @author Nagendra
 * @since 1.3.0
 *
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CWTVerifyRequestDto {

    @NotBlank
    @ApiModelProperty(notes = "COSE Signed Data to verify", example = "", required = true)
    private String coseSignedData;

    /**
     * Application id of decrypting module
     */
    @ApiModelProperty(notes = "Application id to be used for verification", example = "KERNEL", required = false)
    private String applicationId;

    /**
     * Reference Id
     */
    @ApiModelProperty(notes = "Reference Id", example = "SIGN", required = false)
    private String referenceId;

    /**
     * Certificate to be use in JWT Signature verification.
     */
    @ApiModelProperty(notes = "Certificate to be use in JWT Signature verification.", example = "", required = false)
    private String certificateData;

    /**
     * Issuer
     */
    @ApiModelProperty(notes = "Issuer", example = "mosip.io", required = false)
    private String issuer;

    /**
     * Subject
     */
    @ApiModelProperty(notes = "Subject", example = "mosip.io", required = false)
    private String subject;

    /**
     * Flag to validate against trust store.
     */
    @ApiModelProperty(notes = "Flag to validate against trust store.", example = "false", required = false)
    private Boolean validateTrust;

    /**
     * Domain to be considered to validate trust store
     */
    @ApiModelProperty(notes = "Domain to be considered to validate trust store.", example = "", required = false)
    private String domain;
}
