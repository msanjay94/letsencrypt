package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class InvalidAuthorizationException extends CustomException {
	public InvalidAuthorizationException(String message) {
		super(message);
	}
}