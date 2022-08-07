package io.kchoi85.userservice.service;

import java.util.List;

import io.kchoi85.userservice.model.Role;
import io.kchoi85.userservice.model.User;

public interface UserService {
    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);

    User getUser(String username);

    List<User> getUsers();
}
