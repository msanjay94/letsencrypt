package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class InvalidOrderException extends CustomException {
	public InvalidOrderException(String message) {
		super(message);
	}
}