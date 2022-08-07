package io.kchoi85.userservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.kchoi85.userservice.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
