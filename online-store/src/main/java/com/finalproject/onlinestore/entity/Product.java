package com.finalproject.onlinestore.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "products")
public class Product {

    // The unique identifier for the product
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    // The name of the product
    @NotEmpty
    @Size(min = 2, max = 35, message = "Product name must be between 2 and 35 characters.")
    private String productName;

    // The description of the product
    private String description;

    // The price of the product
    private int price;


    // One-to-many relationship with Review, indicating the reviews associated with this product
    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<Review> reviews = new HashSet<>();

    // Many-to-one relationship with Category, indicating the category to which this product belongs
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id", nullable = false)
    private Category category;

}
