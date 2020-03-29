package com.sanjay.acme.v2;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileUtil {
	static void writeToFile(File file, String content, boolean backup) throws IOException {
		writeToFile(file, content.getBytes(), backup);
	}
	
	static void writeToFile(File file, String content) throws IOException {
		writeToFile(file, content, false);
	}
	static void writeToFile(File file, byte[] content, boolean backup) throws IOException {
		FileOutputStream fos = null;
		try {
			if(file.exists()){
				if (backup) {
					String oldContent = readFromFile(file);
					String backupFileName = file.getName()+"-"+System.currentTimeMillis();
					File backupFile = new File(file.getParent()+"/"+backupFileName);
					writeToFile(backupFile, oldContent, false);
				}
				file.delete();
	        }
			file.getParentFile().mkdirs();
			file.createNewFile();
			fos = new FileOutputStream(file);
			fos.write(content);
		} finally {
			fos.close();
		}
	}
	
	static String readFromFile(File file) throws FileNotFoundException, IOException {
		return StreamReader.readStream(new FileInputStream(file));
	}
}
