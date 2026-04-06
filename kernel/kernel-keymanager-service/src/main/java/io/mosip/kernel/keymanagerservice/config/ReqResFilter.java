package io.mosip.kernel.keymanagerservice.config;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.util.ContentCachingRequestWrapper;

/**
 * This class is for input logging of all parameters in HTTP requests
 * 
 * @author Bal Vikash Sharma
 *
 */
public class ReqResFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// init method overriding
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		HttpServletResponse httpServletResponse = (HttpServletResponse) response;
		// Default processing for url ends with .stream
		if (httpServletRequest.getRequestURI().endsWith(".stream")) {
			chain.doFilter(request, response);
			return;
		}
		// Cache only the first 4096 bytes — sufficient for JSON metadata (id, version)
		// without buffering the full encrypted payload in memory at high RPS.
		ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(httpServletRequest, 4096);
		// Pass the actual response directly; response body buffering is not required
		// since ResponseBodyAdviceConfig only reads request metadata, not the response.
		chain.doFilter(requestWrapper, httpServletResponse);

	}

	@Override
	public void destroy() {
		// Auto-generated method stub
	}
}
