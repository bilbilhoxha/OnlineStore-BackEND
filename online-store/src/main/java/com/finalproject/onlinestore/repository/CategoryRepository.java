package com.finalproject.onlinestore.repository;

import com.finalproject.onlinestore.entity.Category;
import org.springframework.data.jpa.repository.JpaRepository;


// Repository interface for managing Category entities
public interface CategoryRepository extends JpaRepository<Category,Long> {
}
