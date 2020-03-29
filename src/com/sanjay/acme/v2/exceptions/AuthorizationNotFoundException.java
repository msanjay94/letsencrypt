package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class AuthorizationNotFoundException extends CustomException {
	public AuthorizationNotFoundException(String message) {
		super(message);
	}
}