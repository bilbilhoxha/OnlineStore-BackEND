package com.finalproject.onlinestore.repository;

import com.finalproject.onlinestore.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;


// Repository interface for managing Product entities
public interface ProductRepository extends JpaRepository<Product,Long> {

}
