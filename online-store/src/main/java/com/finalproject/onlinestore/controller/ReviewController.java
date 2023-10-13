package com.finalproject.onlinestore.controller;

import com.finalproject.onlinestore.dto.ReviewDto;
import com.finalproject.onlinestore.service.ReviewService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@AllArgsConstructor
@RestController
@RequestMapping("/api")
public class ReviewController {

    private ReviewService reviewService;


    // Method to save a review for a specific product
    @PostMapping("/product/{productId}/reviews")
    public ResponseEntity<ReviewDto> save(@PathVariable(name = "productId") long productId, @Valid @RequestBody ReviewDto reviewDto) {
        return new ResponseEntity<>(reviewService.save(productId,reviewDto), HttpStatus.CREATED);

    }

    // Method to retrieve all reviews for a specific product
    @GetMapping("/products/{productId}/reviews")
    public ResponseEntity<List<ReviewDto>> findByProductId(@PathVariable(name = "productId")long productId) {
        return ResponseEntity.ok(reviewService.findAll(productId));
    }

    // Method to retrieve a specific review for a product by review ID
    @GetMapping("/products/{productId}/reviews/{reviewId}")
    public ResponseEntity<ReviewDto> findById(@PathVariable(name = "productId") long productId,@PathVariable(name = "reviewId") long reviewId) {
        return ResponseEntity.ok(reviewService.findById(productId,reviewId));
    }

    // Method to update a specific review for a product
    @PutMapping("/products/{productId}/reviews/{reviewId}")
    public ResponseEntity<ReviewDto> update(@PathVariable(name = "productId") long productId, @PathVariable(name = "reviewId") long reviewId,@Valid @RequestBody ReviewDto reviewDto) {
        return ResponseEntity.ok(reviewService.update(productId,reviewId,reviewDto));
    }

    // Method to delete a specific review for a product
    @DeleteMapping("/products/{productId}/reviews/{reviewId}")
    public  ResponseEntity<String> delete(@PathVariable(name = "productId")long productId,@PathVariable(name = "reviewId") long reviewId) {
        reviewService.delete(productId,reviewId);
        return ResponseEntity.ok("Review with id: "+ reviewId + " was successfully deleted.");
    }
}
