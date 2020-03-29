package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class CustomException extends Exception {
	public CustomException(String message) {
		super(message);
	}
}