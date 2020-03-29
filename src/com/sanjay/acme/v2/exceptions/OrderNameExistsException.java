package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class OrderNameExistsException extends CustomException {
	public OrderNameExistsException(String message) {
		super(message);
	}
}