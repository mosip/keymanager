package io.mosip.kernel.partnercertservice.dto;

import java.time.LocalDateTime;

import lombok.Data;

/**
 * DTO class for download of partner CA Signed certificate & MOSIP Signed Certificate response.
 * 
 * @author Mahammed Taheer
 * @since 1.2.0x
 *
 */
@Data
public class PartnerSignedCertDownloadResponseDto {

    /**
	 * Partner Certificate Data.
	 */
	private String caSignedCertificateData;

	 /**
	 * Partner Certificate Data.
	 */
	private String mosipSignedCertificateData;

	/**
	 * Response timestamp.
	 */
	private LocalDateTime timestamp;
}