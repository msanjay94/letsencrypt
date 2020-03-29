package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class OrderCreationException extends CustomException {
	public OrderCreationException(String message) {
		super(message);
	}
}