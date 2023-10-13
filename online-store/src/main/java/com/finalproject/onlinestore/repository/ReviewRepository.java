package com.finalproject.onlinestore.repository;

import com.finalproject.onlinestore.entity.Product;
import com.finalproject.onlinestore.entity.Review;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

// Repository interface for managing Review entities
public interface ReviewRepository extends JpaRepository<Review,Long> {
    // Custom query method to find reviews by product ID
    public List<Review> findByProductId(long productId);
}
