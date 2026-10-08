package com.example.security.jwt;

import org.springframework.boot.SpringApplication;

public class TestSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.from(SecurityApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
