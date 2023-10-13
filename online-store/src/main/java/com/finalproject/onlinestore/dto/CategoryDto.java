package com.finalproject.onlinestore.dto;

import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class CategoryDto {
    // The unique identifier for the category
    private long id;
    // The name of the category
    @Size(min=2, max=200, message = "nameValidation")
    private String name;
    // The description of the category
    private String description;
}

