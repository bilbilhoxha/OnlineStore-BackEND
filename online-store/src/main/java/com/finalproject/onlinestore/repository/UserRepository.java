package com.finalproject.onlinestore.repository;

import com.finalproject.onlinestore.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// Repository interface for managing User entities
public interface UserRepository extends JpaRepository<User,Long> {

    // Custom query method to find a user by username
    public Optional<User> findByUsername(String username);
}
