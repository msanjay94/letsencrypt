package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class UnknownStatusException extends CustomException {
	public UnknownStatusException(String message) {
		super(message);
	}
}