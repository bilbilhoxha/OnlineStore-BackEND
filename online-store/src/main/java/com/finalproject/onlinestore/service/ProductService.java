package com.finalproject.onlinestore.service;

import com.finalproject.onlinestore.dto.ProductDto;
import com.finalproject.onlinestore.dto.ReviewDto;
import com.finalproject.onlinestore.entity.Category;
import com.finalproject.onlinestore.entity.Product;
import com.finalproject.onlinestore.entity.Review;
import com.finalproject.onlinestore.repository.CategoryRepository;
import com.finalproject.onlinestore.repository.ProductRepository;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@AllArgsConstructor
public class ProductService {

    private ProductRepository productRepository;
    private CategoryRepository categoryRepository;
    private ModelMapper modelMapper;

    public ProductDto save(ProductDto productDto) {

        Category category= categoryRepository.findById(productDto.getCategoryId()).orElseThrow(()->new RuntimeException("No category with this id "+ productDto.getCategoryId()));
        Product product = modelMapper.map(productDto, Product.class);


        Product savedProduct = productRepository.save(product);

        return modelMapper.map(savedProduct,ProductDto.class);
    }


    public List<ProductDto> findAll() {

        List<Product> productList =  productRepository.findAll();
        List<ProductDto> productDtoList = new ArrayList<>();

        for (Product product: productList ) {
            productDtoList.add(modelMapper.map(product,ProductDto.class));

        }
        return productDtoList;
    }


    public ProductDto findById(long studentId) {
        Product existingProduct = productRepository.findById(studentId).orElseThrow(()-> new RuntimeException("Student with id: "+ studentId+" not found"));

        return modelMapper.map(existingProduct,ProductDto.class);
    }

    public ProductDto update(long existingProductId, ProductDto productDto) {
        Product existingProduct = productRepository.findById(existingProductId).orElseThrow(()-> new RuntimeException("Student with id: "+ existingProductId+" not found"));
        Category category= categoryRepository.findById(productDto.getCategoryId()).orElseThrow(()->new RuntimeException("No category with this id "+ productDto.getCategoryId()));

        existingProduct.setId(existingProductId);
        existingProduct.setProductName(productDto.getProductName());
        existingProduct.setDescription(productDto.getDescription());
        existingProduct.setPrice(productDto.getPrice());
        existingProduct.setCategory(category);

        Product savedProduct = productRepository.save(existingProduct);

        return modelMapper.map(savedProduct,ProductDto.class);
    }


    public void delete(long productId) {
        Product existingProduct = productRepository.findById(productId).orElseThrow(()-> new RuntimeException("product with id: "+ productId+" not found"));
        productRepository.delete(existingProduct);
    }


    private Product mapToEntity(ProductDto productDto) {

        Product product = new Product();
        product.setId(productDto.getId());
        product.setProductName(productDto.getProductName());
        product.setDescription(productDto.getDescription());

        return product;
    }


}
