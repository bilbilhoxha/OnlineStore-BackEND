package com.finalproject.onlinestore.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "reviews")
public class Review {

    // The unique identifier for the review
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;


    // The description of the review
    @NotEmpty
    @Size(min = 2, max = 200, message = "Description should be between 2 and 200 characters")
    private String description;


    // The email associated with the review
    @NotBlank
    @Email
    @Size(min = 2, max = 100, message = "Email should be between 2 and 100 characters")
    private String email;


    // Many-to-one relationship with Product, indicating the product to which this review belongs
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;

}
