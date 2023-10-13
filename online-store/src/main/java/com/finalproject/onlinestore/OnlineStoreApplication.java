package com.finalproject.onlinestore;

import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class  OnlineStoreApplication {

	// Bean to provide a ModelMapper instance
	@Bean
	public ModelMapper modelMapper() {
		return new ModelMapper();
	}

	// Main method to run the Spring Boot application
	public static void main(String[] args) {
		SpringApplication.run(OnlineStoreApplication.class, args);
	}

}
