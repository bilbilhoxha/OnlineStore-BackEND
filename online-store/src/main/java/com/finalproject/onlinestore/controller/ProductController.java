package com.finalproject.onlinestore.controller;

import com.finalproject.onlinestore.dto.ProductDto;
import com.finalproject.onlinestore.service.ProductService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@AllArgsConstructor
@RestController
@RequestMapping("/api/products")
public class ProductController {

    ProductService productService;


    // Method to save a new product
    @PostMapping()
    public ResponseEntity<ProductDto> save(@RequestBody ProductDto productDto){
        return new ResponseEntity<> (productService.save(productDto), HttpStatus.CREATED);
    }

    // Method to retrieve all products
    @GetMapping("/findAll")
    public ResponseEntity<List<ProductDto>> findAll(){
        return new ResponseEntity<> (productService.findAll(), HttpStatus.OK);
    }

    // Method to find a product by its ID
    @GetMapping("/{productId}")
    public ResponseEntity<ProductDto> findById(@PathVariable(name ="productId") long productId){
        return new ResponseEntity<> (productService.findById(productId), HttpStatus.OK);
    }

    // Method to update an existing product
    @PutMapping("/update/{productId}")
    public ResponseEntity<ProductDto> update(@PathVariable(name= "productId") long productId,@RequestBody ProductDto productDto){
        return new ResponseEntity<>(productService.update(productId, productDto), HttpStatus.OK);
    }

    // Method to delete a product by its ID
    @DeleteMapping("/delete/{productId}")
    public ResponseEntity<String> delete(@PathVariable(name= "productId") long productId){
        productService.delete(productId);
        return  ResponseEntity.ok("Product with id "+productId+"was succesfully deleted");
    }

}
