package io.mosip.kernel.partnercertservice.dto;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;


@Component("keyManAuthRoles")
@ConfigurationProperties(prefix = "mosip.role.keymanager")
@Getter
@Setter
public class AuthorizedRolesDTO {


	private List<String> postuploadcacertificate;
	
	private List<String> postuploadpartnercertificate;
	
	private List<String> getgetpartnercertificatepartnercertid;
	
	private List<String> postverifycertificatetrust;

	private List<String> getgetpartnersignedcertificatepartnercertid;

}