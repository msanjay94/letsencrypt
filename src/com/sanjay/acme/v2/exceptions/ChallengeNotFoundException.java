package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class ChallengeNotFoundException extends CustomException {
	public ChallengeNotFoundException(String message) {
		super(message);
	}
}