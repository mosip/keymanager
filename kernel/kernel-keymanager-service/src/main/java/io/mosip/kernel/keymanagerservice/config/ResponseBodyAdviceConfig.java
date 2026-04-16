package io.mosip.kernel.keymanagerservice.config;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;
import org.springframework.web.util.ContentCachingRequestWrapper;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.logger.spi.Logger;

/**
 * @author Bal Vikash Sharma
 *
 */
@RestControllerAdvice
public class ResponseBodyAdviceConfig implements ResponseBodyAdvice<ResponseWrapper<?>> {

	private static final Logger mosipLogger = LoggerConfiguration.logConfig(ResponseBodyAdviceConfig.class);


	@Autowired
	private ObjectMapper objectMapper;

	@PostConstruct
	public void init() {
		// Register JavaTimeModule once at startup on the shared singleton ObjectMapper.
		// Registering per-request (150 RPS) creates object churn and mutates shared
		// state concurrently — both corrected here.
		objectMapper.registerModule(new JavaTimeModule());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice#
	 * supports(org.springframework.core.MethodParameter, java.lang.Class)
	 */
	@Override
	public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
		return returnType.hasMethodAnnotation(ResponseFilter.class);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice#
	 * beforeBodyWrite(java.lang.Object, org.springframework.core.MethodParameter,
	 * org.springframework.http.MediaType, java.lang.Class,
	 * org.springframework.http.server.ServerHttpRequest,
	 * org.springframework.http.server.ServerHttpResponse)
	 */
	@Override
	public ResponseWrapper<?> beforeBodyWrite(ResponseWrapper<?> body, MethodParameter returnType,
			MediaType selectedContentType, Class<? extends HttpMessageConverter<?>> selectedConverterType,
			ServerHttpRequest request, ServerHttpResponse response) {

		try {
			HttpServletRequest httpServletRequest = ((ServletServerHttpRequest) request).getServletRequest();

			byte[] cachedBody = null;
			if (httpServletRequest instanceof ContentCachingRequestWrapper) {
				cachedBody = ((ContentCachingRequestWrapper) httpServletRequest).getContentAsByteArray();
			} else if (httpServletRequest instanceof HttpServletRequestWrapper
					&& ((HttpServletRequestWrapper) httpServletRequest)
					.getRequest() instanceof ContentCachingRequestWrapper) {
				cachedBody = ((ContentCachingRequestWrapper) ((HttpServletRequestWrapper) httpServletRequest).getRequest())
						.getContentAsByteArray();
			}

			if (cachedBody != null && cachedBody.length > 0) {
				extractAndSetIdVersion(body, cachedBody);
			}
			body.setErrors(null);
			return body;
		} catch (Exception e) {
			mosipLogger.error("", "", "", e.getMessage());
		}
		return body;
	}

	/**
	 * Extracts only the top-level "id" and "version" fields from the cached
	 * (possibly truncated) request body using a streaming JSON parser.
	 *
	 * ReqResFilter caps the cached body at 4096 bytes. A full ObjectMapper.readValue()
	 * fails with JsonEOFException when the encrypted "data" field spans the truncation
	 * boundary (column 4097). The streaming parser reads token-by-token and stops as
	 * soon as both fields are found — which happens within the first ~100 bytes since
	 * "id" and "version" are always the first two fields in the MOSIP RequestWrapper
	 * JSON envelope — long before any truncation can occur.
	 */
	private void extractAndSetIdVersion(ResponseWrapper<?> body, byte[] cachedBody) {
		try (JsonParser parser = objectMapper.getFactory().createParser(cachedBody)) {
			String id = null;
			String version = null;
			JsonToken token;
			while ((token = parser.nextToken()) != null) {
				if (id != null && version != null) break;
				if (token == JsonToken.FIELD_NAME) {
					String fieldName = parser.getCurrentName();
					token = parser.nextToken();
					if ("id".equals(fieldName) && token == JsonToken.VALUE_STRING) {
						id = parser.getText();
					} else if ("version".equals(fieldName) && token == JsonToken.VALUE_STRING) {
						version = parser.getText();
					} else if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY) {
						if (id != null && version != null) break;
						parser.skipChildren();
					}
				}
			}
			if (id != null) body.setId(id);
			if (version != null) body.setVersion(version);
		} catch (Exception e) {
			mosipLogger.debug("", "", "", "Could not extract id/version from cached request body: " + e.getMessage());
		}
	}

}