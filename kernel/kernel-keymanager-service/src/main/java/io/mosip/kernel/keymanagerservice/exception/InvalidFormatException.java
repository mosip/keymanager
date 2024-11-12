package io.mosip.kernel.keymanagerservice.exception;

import io.mosip.kernel.core.exception.BaseUncheckedException;

/**
 * Custom Exception Class in case of invalid signature format
 * 
 * @author Harsh Vardhan
 * // TODO: which version will this changeset go?
 * @since 1.3.x
 *
 */
public class InvalidFormatException extends BaseUncheckedException {

	/**
	 * Generated serial version id
	 */
	private static final long serialVersionUID = 8621530697947108811L;

	/**
	 * Constructor the initialize Handler exception
	 *
	 * @param errorCode    The errorcode for this exception
	 * @param errorMessage The error message for this exception
	 */
	public InvalidFormatException(String errorCode, String errorMessage) {
		super(errorCode, errorMessage);
	}

}
