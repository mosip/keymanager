package io.mosip.kernel.partnercertservice.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Partner Certificate Download Request DTO
 *
 * @author Nagendra
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representation request to list partner certificate based on certificate type.")
public class CaCertTypeListRequestDto {

    /**
     * Certificate Type
     */
    @ApiModelProperty(notes = "Partner Certificate Type", required = false)
    private String caCertificateType;

    /**
     * Domain Name
     */
    @ApiModelProperty(notes = "Domain Name", required = false)
    private String partnerDomain;

    @ApiModelProperty(notes = "Flag to force exclude the mosip CA Certificates", example = "false", required = false)
    private Boolean excludeMosipCA;

    /**
     * Sort Direction: ASC, DESC
     */
    @ApiModelProperty(notes = "Sort Direction", required = false)
    String sortOrder;
    /**
     * Page Number
     */
    @ApiModelProperty(notes = "Page Number", required = false)
    @NotNull(message = KeymanagerConstant.INVALID_REQUEST)
    private int pageNumber;

    /**
     * Number of Certificate
     */
    @ApiModelProperty(notes = "Number of Certificate", required = false)
    @NotNull(message = KeymanagerConstant.INVALID_REQUEST)
    private int pageSize;

    /**
     * CA Certificate Id
     */
    @ApiModelProperty(notes = "CA Certificate Id", required = false)
    private String certId;

    /**
     * Ca Certificate Issued To
     */
    @ApiModelProperty(notes = "Issued To", required = false)
    private String issuedTo;

    /**
     * Ca Certificate Issued By
     */
    @ApiModelProperty(notes = "Issued By", required = false)
    private String issuedBy;

    /**
     * Ca Certificate Valid From
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    @ApiModelProperty(notes = "Valid From", required = false)
    private LocalDateTime validFromDate;

    /**
     * Ca Certificate Valid Till
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    @ApiModelProperty(notes = "Valid Till", required = false)
    private LocalDateTime validTillDate;

    /**
     * Ca Certificate uploaded time
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    @ApiModelProperty(notes = "Upload Time", required = false)
    private LocalDateTime uploadTime;

    /**
     * Sort By Field Name
     */
    @ApiModelProperty(notes = "Sort By Field", required = false)
    private String sortByFieldName;
}