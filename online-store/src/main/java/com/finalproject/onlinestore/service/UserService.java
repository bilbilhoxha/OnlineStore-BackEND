package com.finalproject.onlinestore.service;

import com.finalproject.onlinestore.entity.User;
import com.finalproject.onlinestore.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private UserRepository userRepository;

    private PasswordEncoder passEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passEncoder) {
        this.userRepository = userRepository;
        this.passEncoder = passEncoder;
    }

    public User save(User user) {
        user.setPassword(passEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public User updateUserById(User user, Long id) {
        Optional<User> existingUser = userRepository.findById(id);

        if (existingUser.isPresent()) {
            existingUser.get().setFirstName(user.getFirstName());
            existingUser.get().setLastName(user.getLastName());
            existingUser.get().setEmail(user.getEmail());
            existingUser.get().setRoles(user.getRoles());
            existingUser.get().setUsername(user.getUsername());

            //      String encodedPassword = passEncoder.encode(user.getPassword());
            //      existingUser.get().setPassword(encodedPassword);

            existingUser.get().setPassword(passEncoder.encode(user.getPassword()));

            existingUser.get().setId(id);

            userRepository.save(existingUser.get());

        } else throw new RuntimeException("User with id: " + id + "was not found");

        return existingUser.get();
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }

    public User findById(long id) {
        Optional<User> existingUser = userRepository.findById(id);
        if (existingUser.isPresent()) {
            existingUser.get();
        } else throw new RuntimeException("User with id: " + id + "was not found");
        return existingUser.get();
    }


    public void deleteUserById(long id) {
        Optional<User> existingUser = userRepository.findById(id);
        if (existingUser.isPresent()) {
            userRepository.delete(existingUser.get());
        }
    }
}
