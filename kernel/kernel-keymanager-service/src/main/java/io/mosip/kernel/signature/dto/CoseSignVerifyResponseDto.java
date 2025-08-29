package io.mosip.kernel.signature.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The Class CoseSignVerifyResponseDto.
 *
 * @author Nagendra
 * @since 1.3.0-SNAPSHOT
 *
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CoseSignVerifyResponseDto {

    /**
     * The signature verification status.
     */
    private boolean signatureValid;

    /**
     * The signature verification message.
     */
    private String message;

    /**
     * The Trust validation status.
     */
    private String trustValid;
}
