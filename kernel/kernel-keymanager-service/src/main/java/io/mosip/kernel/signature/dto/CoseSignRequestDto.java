package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CoseSignRequestDto {

    @NotBlank
    @ApiModelProperty(notes = "Base64 encoded Data to sign", example = "ewogICAiYW55S2V5IjogIlRlc3QgSnNvbiIKfQ", required = true)
    String payload;

    /**
     * Application id
     */
    @ApiModelProperty(notes = "Application id to be used for signing", example = "KERNEL", required = false)
    String applicationId;

    /**
     * Refrence Id
     */
    @ApiModelProperty(notes = "Refrence Id to be used for signing", example = "SIGN", required = false)
    String referenceId;

    /**
     * Protected Headers
     */
    @ApiModelProperty(notes = "Protected Headers", example = "alg:ES256", required = false)
    Map<String, Object> protectedHeader;

    /**
     * Unprotected Header
     */
    @ApiModelProperty(notes = "Unprotected Headers in COSE format", example = "kid:123", required = false)
    Map<String, Object> unprotectedHeader;

    /**
     * Algorithm to use for data signing
     */
    @ApiModelProperty(notes = "Algorithm to use for data signing", example = "PS256", required = false)
    String algorithm;
}
