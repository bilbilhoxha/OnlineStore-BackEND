package com.finalproject.onlinestore.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "roles")
public class Role {

    // The unique identifier for the role
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    // The role name
    private String role;
}