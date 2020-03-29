package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class ExpiredAuthorizationException extends CustomException {
	public ExpiredAuthorizationException(String message) {
		super(message);
	}
}