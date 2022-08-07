package io.kchoi85.userservice.service.impl;

import java.util.List;

import io.kchoi85.userservice.model.Role;
import io.kchoi85.userservice.model.User;
import io.kchoi85.userservice.service.UserService;

public class UserServiceImpl implements UserService {

    public UserServiceImpl() {
        super();
    }

    @Override
    public User saveUser(User user) {
        return null;
    }

    @Override
    public Role saveRole(Role role) {
        return null;
    }

    @Override
    public void addRoleToUser(String username, String roleName) {

    }

    @Override
    public User getUser(String username) {
        return null;
    }

    @Override
    public List<User> getUsers() {
        return null;
    }

}
