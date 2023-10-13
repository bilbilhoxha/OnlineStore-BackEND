package com.finalproject.onlinestore.controller;



import com.finalproject.onlinestore.dto.CategoryDto;
import com.finalproject.onlinestore.service.CategoryService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@AllArgsConstructor
@RestController
@RequestMapping("/api/categories")
public class CategoryController {
    private CategoryService categoryService;


    // Method to save a new category
    @PostMapping
    public ResponseEntity<CategoryDto> save(@Valid @RequestBody CategoryDto categoryDto) {
        return new ResponseEntity<>(categoryService.save(categoryDto), HttpStatus.CREATED);
    }


    // Method to find a category by its ID
    @GetMapping("/{categoryId}")
    public ResponseEntity<CategoryDto> findById(@PathVariable(name = "categoryId") long categoryId) {
        return new ResponseEntity<>(categoryService.findById(categoryId), HttpStatus.OK);
    }

    // Method to retrieve all categories
    @GetMapping
    public ResponseEntity<List<CategoryDto>> findAll() {
        return ResponseEntity.ok(categoryService.findAll());
    }


    // Method to update an existing category
    @PutMapping("/{categoryId}")
    public ResponseEntity<CategoryDto> update(@Valid @RequestBody CategoryDto categoryDto, @PathVariable(name = "categoryId") long categoryId) {
        return ResponseEntity.ok(categoryService.update(categoryDto, categoryId));
    }

    // Method to delete a category by its ID
    @DeleteMapping("/{categoryId}")
    public ResponseEntity<String> delete(@PathVariable(name = "categoryId") long categoryId) {
        categoryService.delete(categoryId);
        return ResponseEntity.ok("Category with id: " + categoryId + " was successfully deleted");
    }
}

