package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class AccountCreationException extends CustomException {
	public AccountCreationException(String message) {
		super(message);
	}
}