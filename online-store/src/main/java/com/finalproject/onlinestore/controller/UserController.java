package com.finalproject.onlinestore.controller;

import com.finalproject.onlinestore.entity.User;
import com.finalproject.onlinestore.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/user")
public class UserController {

    private UserService userService;

    // Constructor injection of UserService
    public UserController(UserService userService) {
        this.userService = userService;
    }

    // Method to save a new user
    @PostMapping("/save")
    public ResponseEntity<User> save(@Valid @RequestBody User user) {
        return new  ResponseEntity<User> (userService.save(user), HttpStatus.CREATED);
    }

    // Method to update a user by their ID
    @PutMapping("/{id}")
    public ResponseEntity<User> updateById(@Valid @RequestBody User user, @PathVariable("id") long id) {
        return ResponseEntity.ok(userService.updateUserById(user, id));
    }
    // Method to retrieve all users
    @GetMapping
    public List<User> findAll() {
        return userService.findAll();
    }

    // Method to find a user by their ID
    @GetMapping("/findById/{id}")
    public User findByUserId(@PathVariable("id") long id) {
        return userService.findById(id);
    }

    // Method to delete a user by their ID
    @DeleteMapping("/deleteById/{id}")
    public String deleteById(@PathVariable("id") long id) {
        userService.deleteUserById(id);
        return "User with id: "+id+" was successfully deleted!";
    }

}
