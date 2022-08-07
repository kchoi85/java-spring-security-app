package io.kchoi85.userservice;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.kchoi85.userservice.model.Role;
import io.kchoi85.userservice.model.User;
import io.kchoi85.userservice.service.UserService;

@SpringBootApplication
public class UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_USER"));

			userService.saveUser(new User(null, "Kihoon", "kchoi85", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Ree", "daniel102", "5678", new ArrayList<>()));

			userService.addRoleToUser("kchoi85", "ROLE_ADMIN");
		};
	}

}
