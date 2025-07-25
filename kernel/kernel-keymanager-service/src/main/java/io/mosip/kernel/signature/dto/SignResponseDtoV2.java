package io.mosip.kernel.signature.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignResponseDtoV2 {

    /**
     * Signed Data
     */
    private String signedData;

    /**
     * Key ID used for signing
     */
    private String keyId;

    /**
     * Certificate used for signing
     */
    private String certificate;

    /**
     * Signature Algorithm used
     */
    private String signatureAlgorithm;

    /**
     * response time
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private LocalDateTime timestamp;
}
