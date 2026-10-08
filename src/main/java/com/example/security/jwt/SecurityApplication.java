package com.example.security.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.TimeZone;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		// Postgres rejects the legacy name "Asia/Calcutta" that Windows Java reports.
		// Must run BEFORE SpringApplication.run, so the DB driver sees the new name.
		TimeZone.setDefault(TimeZone.getTimeZone("Asia/Kolkata"));
		SpringApplication.run(SecurityApplication.class, args);
	}

}
