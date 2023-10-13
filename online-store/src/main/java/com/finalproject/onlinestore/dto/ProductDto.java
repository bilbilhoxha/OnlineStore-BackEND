package com.finalproject.onlinestore.dto;

import com.finalproject.onlinestore.entity.Review;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
public class ProductDto {
    private long id;
    @Size(min = 2, max = 35, message = "Product name must be between 2 and 35 characters.")
    private String productName;

    private String description;
    private int price;
    private Set<Review> reviews ;
    private long categoryId;
}
