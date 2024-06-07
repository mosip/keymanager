package io.mosip.kernel.keymanagerservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;

/**
 * Configuration class for swagger config
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
@Configuration
public class SwaggerConfig {

	@Value("${openapi.info.title:Key Manager Service}")
	private String title;

	@Value("${openapi.info.version:1.0}")
	private String version;

	@Value("${openapi.info.description:Rest Endpoints for operations related to key management and crypto operations}")
	private String description;

	@Value("${openapi.info.license.name:Mosip}")
	private String licenseName;

	@Value("${openapi.info.license.url:https://docs.mosip.io/platform/license}")
	private String licenseUrl;

	@Value("${openapi.service.server.url:http://localhost:8088/v1/keymanager}")
	private String serverUrl;

	@Value("${openapi.service.server.description:Key Manager Service}")
	private String serverDesc;

	@Bean
	public OpenAPI openApi() {
		OpenAPI api = new OpenAPI().components(new Components())
				.info(new Info().title(title)
						.version(version)
						.description(description)
						.license(new License().name(licenseName).url(licenseUrl)));

		api.addServersItem(new Server().description(serverDesc).url(serverUrl));
		return api;
	}
}
