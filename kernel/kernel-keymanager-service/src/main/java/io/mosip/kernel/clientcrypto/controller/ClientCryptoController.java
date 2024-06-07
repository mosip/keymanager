package io.mosip.kernel.clientcrypto.controller;


import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.clientcrypto.dto.PublicKeyRequestDto;
import io.mosip.kernel.clientcrypto.dto.PublicKeyResponseDto;
import io.mosip.kernel.clientcrypto.dto.TpmCryptoRequestDto;
import io.mosip.kernel.clientcrypto.dto.TpmCryptoResponseDto;
import io.mosip.kernel.clientcrypto.dto.TpmSignRequestDto;
import io.mosip.kernel.clientcrypto.dto.TpmSignResponseDto;
import io.mosip.kernel.clientcrypto.dto.TpmSignVerifyRequestDto;
import io.mosip.kernel.clientcrypto.dto.TpmSignVerifyResponseDto;
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoManagerService;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * @author Anusha Sunkada
 * @since 1.1.2
 */

@SuppressWarnings("java:S5122") // Need CrossOrigin access for all the APIs, added to ignore in sonarCloud Security hotspots.
@CrossOrigin
@RestController
@Tag(name = "clientcrypto", description = "Operation related to offline Encryption and Decryption")
public class ClientCryptoController {

    @Autowired
    private ClientCryptoManagerService clientCryptoManagerService;

    /**
	 *
	 * @param tpmSignRequestDtoRequestWrapper
	 * @return
	 */
	@Operation(summary = "Sign data using tpm", description = "Sign data using tpm", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPostcssign())")
    //@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @ResponseFilter
    @PostMapping(value = "/cssign", produces = "application/json")
    public ResponseWrapper<TpmSignResponseDto> signData(@RequestBody @Valid RequestWrapper<TpmSignRequestDto>
                                                                             tpmSignRequestDtoRequestWrapper) {
        ResponseWrapper<TpmSignResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.csSign(tpmSignRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param tpmSignVerifyRequestDtoRequestWrapper
     * @return
     */
	@Operation(summary = "Verify signature", description = "Verify signature", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPostcsverifysign())")
    @ResponseFilter
    @PostMapping(value = "/csverifysign", produces = "application/json")
    public ResponseWrapper<TpmSignVerifyResponseDto> verifySignature(@RequestBody @Valid RequestWrapper<TpmSignVerifyRequestDto>
                                                                  tpmSignVerifyRequestDtoRequestWrapper) {
        ResponseWrapper<TpmSignVerifyResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.csVerify(tpmSignVerifyRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param tpmCryptoRequestDtoRequestWrapper
     * @return
     */
	@Operation(summary = "Encrypt data using tpm", description = "Encrypt data using tpm", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPosttpmencrypt())")
    @ResponseFilter
    @PostMapping(value = "/tpmencrypt", produces = "application/json")
    public ResponseWrapper<TpmCryptoResponseDto> tpmEncrypt(@RequestBody @Valid RequestWrapper<TpmCryptoRequestDto>
                                                                             tpmCryptoRequestDtoRequestWrapper) {
        ResponseWrapper<TpmCryptoResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.csEncrypt(tpmCryptoRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param tpmCryptoRequestDtoRequestWrapper
     * @return
     */
	@Operation(summary = "Decrypt data using tpm", description = "Decrypt data using tpm", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPosttpmdecrypt())")
    @ResponseFilter
    @PostMapping(value = "/tpmdecrypt", produces = "application/json")
    public ResponseWrapper<TpmCryptoResponseDto> tpmDecrypt(@RequestBody @Valid RequestWrapper<TpmCryptoRequestDto>
                                                                    tpmCryptoRequestDtoRequestWrapper) {
        ResponseWrapper<TpmCryptoResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.csDecrypt(tpmCryptoRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param publicKeyRequestDtoRequestWrapper
     * @return
     */
	@Operation(summary = "Get signinging public key", description = "Get signinging public key", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPosttpmsigningpublickey())")
    @ResponseFilter
    @PostMapping(value = "/tpmsigning/publickey", produces = "application/json")
    public ResponseWrapper<PublicKeyResponseDto> getSigningPublicKey(@RequestBody @Valid RequestWrapper<PublicKeyRequestDto>
                                                                    publicKeyRequestDtoRequestWrapper) {
        ResponseWrapper<PublicKeyResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.getSigningPublicKey(publicKeyRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }

    /**
     *
     * @param publicKeyRequestDtoRequestWrapper
     * @return
     */
	@Operation(summary = "Get encryption public key", description = "Get encryption public key", tags = { "clientcrypto" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION','TEST', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
    @PreAuthorize("hasAnyRole(@clientCryptoAuthRoles.getPosttpmencryptionpublickey())")
    @ResponseFilter
    @PostMapping(value = "/tpmencryption/publickey", produces = "application/json")
    public ResponseWrapper<PublicKeyResponseDto> getEncPublicKey(@RequestBody @Valid RequestWrapper<PublicKeyRequestDto>
                                                                             publicKeyRequestDtoRequestWrapper) {
        ResponseWrapper<PublicKeyResponseDto> responseDtoResponseWrapper = new ResponseWrapper<>();
        responseDtoResponseWrapper.setResponse(clientCryptoManagerService.getEncPublicKey(publicKeyRequestDtoRequestWrapper.getRequest()));
        return responseDtoResponseWrapper;
    }
}
