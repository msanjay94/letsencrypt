package com.sanjay.acme.v2.exceptions;

@SuppressWarnings("serial")
public class ChallengeFailedException extends CustomException {
	public ChallengeFailedException(String message) {
		super(message);
	}
}