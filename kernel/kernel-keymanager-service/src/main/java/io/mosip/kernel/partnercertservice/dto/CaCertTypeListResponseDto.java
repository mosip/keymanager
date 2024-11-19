package io.mosip.kernel.partnercertservice.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO class for List the CA Certificate Based on the Certificate Type.
 *
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "certificate Dto class representation")
public class CaCertTypeListResponseDto {

    /**
     * CA Certificate Type
     */
    @ApiModelProperty(notes = "CA Certificate Type", required = true)
    private String caCertificateType;

    /**
     * Partner Domain.
     */
    @ApiModelProperty(notes = "Partner Domain", required = true)
    private String partnerDomain;

    /**
     * CA Certificate Id
     */
    @ApiModelProperty(notes = "CA Certificate Id", required = true)
    private String certId;

    /**
     * Ca Certificate Issued To
     */
    @ApiModelProperty(notes = "Issued To", required = true)
    private String issuedTo;

    /**
     * Ca Certificate Issued By
     */
    @ApiModelProperty(notes = "Issued By", required = true)
    private String issuedBy;

    /**
     * Ca Certificate Valid From
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    @ApiModelProperty(notes = "Valid From", required = true)
    private LocalDateTime validFromDate;

    /**
     * Ca Certificate Valid Till
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    @ApiModelProperty(notes = "Valid Till", required = true)
    private LocalDateTime validTillDate;

    /**
     * Ca Certificate uploaded time
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    @ApiModelProperty(notes = "Upload Time", required = true)
    private LocalDateTime uploadTime;

    /**
     * Ca certificate status
     */
    @ApiModelProperty(notes = "status", required = true)
    private boolean status;
}