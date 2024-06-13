package io.mosip.kernel.keymanagerservice.test.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.fasterxml.jackson.module.afterburner.AfterburnerModule;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class TestSecurityConfig {

	@Bean
	public HttpFirewall defaultHttpFirewall() {
		return new DefaultHttpFirewall();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().requestMatchers(allowedEndPoints()).and().httpFirewall(defaultHttpFirewall());
	}

	private String[] allowedEndPoints() {
		return new String[] { "/assets/**", "/icons/**", "/screenshots/**", "/favicon**", "/**/favicon**", "/css/**",
				"/js/**", "/*/error**", "/*/webjars/**", "/*/v2/api-docs", "/*/configuration/ui",
				"/*/configuration/security", "/*/swagger-resources/**", "/*/swagger-ui.html" };
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable())
				.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedEntryPoint()))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests((authz) -> authz.anyRequest().authenticated())
				.userDetailsService(userDetailsService());

		return http.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("*", "POST", "PUT", "GET", "OPTIONS", "DELETE", "PATCH")); 
		configuration.setAllowedHeaders(Arrays.asList("*"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
	
	@Bean
	public AuthenticationEntryPoint unauthorizedEntryPoint() {
		return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		List<UserDetails> users = new ArrayList<>();
		users.add(new User("reg-officer", "mosip",
				Arrays.asList(new SimpleGrantedAuthority("ROLE_REGISTRATION_OFFICER"))));
		users.add(new User("reg-supervisor", "mosip",
				Arrays.asList(new SimpleGrantedAuthority("ROLE_REGISTRATION_SUPERVISOR"))));
		users.add(new User("reg-admin", "mosip", Arrays.asList(new SimpleGrantedAuthority("ROLE_REGISTRATION_ADMIN"))));
		users.add(new User("reg-processor", "mosip",
				Arrays.asList(new SimpleGrantedAuthority("ROLE_REGISTRATION_PROCESSOR"))));
		users.add(new User("id-auth", "mosip", Arrays.asList(new SimpleGrantedAuthority("ROLE_ID_AUTHENTICATION"))));
		users.add(new User("individual", "mosip", Arrays.asList(new SimpleGrantedAuthority("ROLE_INDIVIDUAL"))));
		users.add(new User("test", "mosip", Arrays.asList(new SimpleGrantedAuthority("ROLE_TEST"))));
		return new InMemoryUserDetailsManager(users);
	}

	@Bean
	public AfterburnerModule afterburnerModule() {
		return new AfterburnerModule();
	}

	@Bean
	public WebMvcConfigurer corsConfigurer() {
		return new WebMvcConfigurer() {
			@Override
			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/**").allowedMethods("*");
			}
		};
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}