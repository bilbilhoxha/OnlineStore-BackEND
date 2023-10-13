package com.finalproject.onlinestore.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;


@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users",uniqueConstraints = {@UniqueConstraint(columnNames = {"username"}),@UniqueConstraint(columnNames = {"email"})})
public class User {

    // The unique identifier for the user
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // The first name of the user
    @NotEmpty
    @Size(min = 2,max = 50,message = "First name must be between 2 and 50 characters.")
    private String firstName;


    // The last name of the user
    @NotEmpty
    @Size(min = 2,max = 50,message = "Last name must be between 2 and 50 characters.")
    private String lastName;


    // The last name of the user
    @Column(nullable = false, unique = true)
    private String username;

    // The email of the user (unique)
    @Email
    @Column(nullable = false, unique = true)
    private String email;


    // The password of the user
    @Column(nullable = false)
    private String password;

    // Many-to-many relationship with Role, indicating the roles assigned to this user
    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id")
    )
    private Set<Role> roles;
}
