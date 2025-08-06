package io.mosip.kernel.keymanagerservice.dto;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;


@Component("KeyManagerAuthRoles")
@ConfigurationProperties(prefix = "mosip.role.keymanager")
@Getter
@Setter
public class AuthorizedRolesDTO {

	private List<String> postgeneratemasterkeyobjecttype;
	
	private List<String> getgetcertificate;
	
	private List<String> postgeneratecsr;
	
	private List<String> postuploadcertificate;
	
	private List<String> postuploadotherdomaincertificate;
	
	private List<String> postgeneratesymmetrickey;
	
	private List<String> putrevokekey;

	private List<String> getcertificatechain;

}