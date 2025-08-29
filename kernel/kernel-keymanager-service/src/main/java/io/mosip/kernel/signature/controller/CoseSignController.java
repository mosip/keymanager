package io.mosip.kernel.signature.controller;

import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.dto.CoseSignResponseDto;
import io.mosip.kernel.signature.dto.CoseSignVerifyRequestDto;
import io.mosip.kernel.signature.dto.CoseSignVerifyResponseDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author Nagendra
 * @since 1.3.0
 *
 */

@RestController
@CrossOrigin
@Tag(name = "cosesigncontroller", description = "Operation related COSE signature")
public class CoseSignController {

    /**
     * Signature service
     */
    @Autowired
    CoseSignatureService service;

    /**
     * Function to do COSE Sign for the input data using COSE algorithm
     *
     * @param requestDto {@link CoseSignRequestDto} having required fields.
     * @return The {@link CoseSignResponseDto}
     */
    @Operation(summary = "Function to do COSE Sign for the input data using COSE algorithm", description = "Function to COSE sign data", tags = { "cosesignaturecontroller" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    @ResponseFilter
    @PreAuthorize("hasAnyRole(@signAuthRoles.getPostcosesign())")
    @PostMapping(value = "/coseSign")
    public ResponseWrapper<CoseSignResponseDto> coseSign(@RequestBody @Valid RequestWrapper<CoseSignRequestDto> requestDto) {
        CoseSignResponseDto coseSignResponse = service.coseSign(requestDto.getRequest());
        ResponseWrapper<CoseSignResponseDto> response = new ResponseWrapper<>();
        response.setResponse(coseSignResponse);
        return response;
    }

    /**
     * Function to do verification of COSE signed data
     *
     * @param requestDto {@link CoseSignVerifyRequestDto} having required fields.
     * @return The {@link CoseSignVerifyResponseDto} containing verification status and message
     */
    @Operation(summary = "Function to do COSE Sign for the input data using COSE algorithm", description = "Function to COSE sign data", tags = { "cosesignaturecontroller" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    @ResponseFilter
    @PreAuthorize("hasAnyRole(@signAuthRoles.getPostcoseverify())")
    @PostMapping(value = "/coseVerify")
    public ResponseWrapper<CoseSignVerifyResponseDto> coseVerify(@RequestBody @Valid RequestWrapper<CoseSignVerifyRequestDto> requestDto) {
        CoseSignVerifyResponseDto coseSignVerifyResponse = service.coseVerify(requestDto.getRequest());
        ResponseWrapper<CoseSignVerifyResponseDto> response = new ResponseWrapper<>();
        response.setResponse(coseSignVerifyResponse);
        return response;
    }
}
