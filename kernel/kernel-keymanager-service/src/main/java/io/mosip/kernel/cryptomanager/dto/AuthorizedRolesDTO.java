package io.mosip.kernel.cryptomanager.dto;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;


@Component("cryptoManagerAuthRoles")
@ConfigurationProperties(prefix = "mosip.role.keymanager")
@Getter
@Setter
public class AuthorizedRolesDTO
{

	private List<String> postencrypt;
		  
    private List<String> postdecrypt;
		  
    private List<String> postencryptwithpin;
	
	private List<String> postdecryptwithpin;
	
	private List<String> postjwtencrypt;
	
	private List<String> postjwtdecrypt;

}