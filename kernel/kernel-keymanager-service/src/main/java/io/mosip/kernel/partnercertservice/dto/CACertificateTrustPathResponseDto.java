package io.mosip.kernel.partnercertservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO class for download of p7b File for CA Certificate.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CACertificateTrustPathResponseDto {
//
//    /**
//     * format of certificate
//     */
//
//    private String Format;
    /**
     * CA Certificate Data
     */
    private String p7bFile;

    /**
     * Response Timestamp
     */
    private LocalDateTime timestamp;
}
