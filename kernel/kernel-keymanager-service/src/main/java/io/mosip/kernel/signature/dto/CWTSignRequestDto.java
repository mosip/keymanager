package io.mosip.kernel.signature.dto;

import com.authlete.cbor.CBORItem;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Request DTO for CWT data signing.
 *
 * @author Nagendra
 * @since 1.3.0
 *
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CWTSignRequestDto {
    /**
     * Base64 encoded JSON Data to sign
     */
    @ApiModelProperty(notes = "Base64 encoded Data to sign", example = "ewogICAiYW55S2V5IjogIlRlc3QgSnNvbiIKfQ", required = true)
    private String payload;

    /**
     * claim 169 data Payload
     */
    @ApiModelProperty(notes = "claim 169 data Payload", example = "", required = false)
    private String claim169Payload;

    /**
     * Application id
     */
    @ApiModelProperty(notes = "Application id to be used for signing", example = "KERNEL", required = false)
    private String applicationId;

    /**
     * Refrence Id
     */
    @ApiModelProperty(notes = "Refrence Id to be used for signing", example = "SIGN", required = false)
    private String referenceId;

    /**
     * Protected Headers
     */
    @ApiModelProperty(notes = "Protected Headers", example = "alg:ES256", required = false)
    private Map<String, Object> protectedHeader;

    /**
     * Unprotected Header
     */
    @ApiModelProperty(notes = "Unprotected Headers in COSE format", example = "kid:123", required = false)
    private Map<String, Object> unprotectedHeader;

    /**
     * Algorithm to use for data signing
     */
    @ApiModelProperty(notes = "Algorithm to use for data signing", example = "PS256", required = false)
    private String algorithm;

    /**
     * Issuer
     */
    @ApiModelProperty(notes = "Issuer", example = "MOSIP", required = false)
    private String issuer;

    /**
     * Subject
     */
    @ApiModelProperty(notes = "Subject", example = "mosip.com", required = false)
    private String subject;

    /**
     * Audience
     */
    @ApiModelProperty(notes = "Audience", example = "mosip.com", required = false)
    private String audience;

    /**
     * Expire date in number of days
     */
    @ApiModelProperty(notes = "Expire date in number of days", example = "30", required = false)
    private Integer expireDays;

    /**
     * Not Before date in number of days
     */
    @ApiModelProperty(notes = "Not Before date in number of days", example = "1", required = false)
    private Integer notBeforeDays;

    /**
     * CWT Id
     */
    @ApiModelProperty(notes = "CWT Id", example = "123", required = false)
    private String CWTId;
}
