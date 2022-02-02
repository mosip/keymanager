package io.mosip.kernel.signature.dto;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;


@Component("signAuthRoles")
@ConfigurationProperties(prefix = "mosip.role.keymanager")
@Getter
@Setter
public class AuthorizedRolesDTO
{

	private List<String> postsign;
	
	private List<String> postvalidate;
	
	private List<String> postpdfsign;
	
	private List<String> postjwtsign;
	
	private List<String> postjwtverify;

	private List<String> postjwssign;
}