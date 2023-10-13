package com.finalproject.onlinestore.security;

import com.finalproject.onlinestore.entity.User;
import com.finalproject.onlinestore.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@AllArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;
    // Load user details by username for authentication
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> existingUser = userRepository.findByUsername(username);

        // Check if the user exists
        if (existingUser.isPresent()) {
            return new MyUserDetails(existingUser.get());
        }else throw new UsernameNotFoundException("User with username: " + username+ " was not found!");

    }

}
