package com.finalproject.onlinestore.repository;

import com.finalproject.onlinestore.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

// Repository interface for managing Role entities
public interface RoleRepository extends JpaRepository<Role,Long> {
}
