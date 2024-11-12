package io.mosip.kernel.partnercertservice.dto;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Class representing All Partner Certificate Data Response")
public class CaCertificateChainResponseDto {

    /**
     * Page Number
     */
    private int pageNumber;

    /**
     * Number of records in the Page
     */
    private int pageSize;

    /**
     * Total Number of Records
     */
    private long totalRecords;

    /**
     * Total number of Pages
     */
    private int totalPages;

    /**
     * Field for CA Certificate
     */
    private CaCertTypeListResponseDto[] allPartnerCertificates;

}
