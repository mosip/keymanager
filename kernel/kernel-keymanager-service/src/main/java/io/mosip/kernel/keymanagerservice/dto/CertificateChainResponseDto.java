package io.mosip.kernel.keymanagerservice.dto;

import io.swagger.annotations.Api;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Api(description = "Class representing a Certificate Chain Response")
public class CertificateChainResponseDto {

    /**
     * The certificate chain in p7b.
     */
    private String certificatesTrustPath;

    /**
     * Timestamp.
     */
    private LocalDateTime timestamp;
}
