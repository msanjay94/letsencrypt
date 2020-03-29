package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class FailedLocalValidationException extends CustomException {
	public FailedLocalValidationException(String message) {
		super(message);
	}
}