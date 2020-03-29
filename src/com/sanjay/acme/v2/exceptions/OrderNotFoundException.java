package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class OrderNotFoundException extends CustomException {
	public OrderNotFoundException(String message) {
		super(message);
	}
}