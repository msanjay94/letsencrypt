package com.sanjay.acme.v2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class StreamReader {
	static String readStream(InputStream inputStream) throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		StringBuilder output = new StringBuilder();
		for (String line = reader.readLine(); line != null; line = reader.readLine()) {
			output.append(line).append(System.lineSeparator());
		}
		return output.toString();
	}
}
