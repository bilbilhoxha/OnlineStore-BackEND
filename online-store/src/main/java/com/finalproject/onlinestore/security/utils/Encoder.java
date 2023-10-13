package com.finalproject.onlinestore.security.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Encoder {

    // Static method to encode a password using BCryptPasswordEncoder

    private static PasswordEncoder passwordEncoder;

    public static void main(String[] args){

        // Create an instance of BCryptPasswordEncoder
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


        // Encode a password and print the encoded value
        System.out.println(passwordEncoder.encode("123"));
    }
}
