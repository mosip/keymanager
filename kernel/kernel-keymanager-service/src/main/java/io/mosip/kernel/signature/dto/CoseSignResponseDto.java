package io.mosip.kernel.signature.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CoseSignResponseDto {

    /**
     * Base64 encoded COSE signed data
     */
    String signedData;

    /**
     * response time
     */
    LocalDateTime timestamp;
}
