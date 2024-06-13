package io.mosip.kernel.signature.dto;

import jakarta.validation.constraints.NotBlank;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PublicKeyRequestDto {
	@NotBlank
	private String signature;
	@NotBlank
	private String data;
	@NotBlank
	private String publickey;

}
