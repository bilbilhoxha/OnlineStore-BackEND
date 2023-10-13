package com.finalproject.onlinestore.dto;

import com.finalproject.onlinestore.entity.Product;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ReviewDto {

    private long id;

    @NotEmpty
    @Size(min = 2, max = 200, message = "Description should be between 2 and 200 characters")
    private String description;

    @NotBlank
    @Email
    @Size(min = 2, max = 100, message = "Email should be between 2 and 100 characters")
    private String email;


}
