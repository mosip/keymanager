package io.mosip.kernel.partnercertservice.dto;

import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representing request to download p7b file for ca certificate")
public class CAp7bFileDownloadRequestDto {

    /**
     * Certificate ID of CA Certificate
     */
    @ApiModelProperty(notes = "CA Certificate ID", required = true)
    @NotBlank(message = KeymanagerConstant.INVALID_REQUEST)
    String caCertId;
}
