package io.kchoi85.userservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.kchoi85.userservice.model.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
