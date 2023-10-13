package com.finalproject.onlinestore.service;

import com.finalproject.onlinestore.dto.ProductDto;
import com.finalproject.onlinestore.dto.ReviewDto;
import com.finalproject.onlinestore.entity.Product;
import com.finalproject.onlinestore.entity.Review;
import com.finalproject.onlinestore.repository.ProductRepository;
import com.finalproject.onlinestore.repository.ReviewRepository;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Service
@AllArgsConstructor
public class ReviewService {
    private ProductRepository productRepository;
    private ReviewRepository reviewRepository;
    private ModelMapper modelMapper;

    public ReviewDto save(long productId, ReviewDto reviewDto) {

        Product existingProduct = productRepository.findById(productId).orElseThrow(() -> new RuntimeException("Product with id: " + productId + " not found"));

        Review review = mapToEntity(reviewDto);
        review.setProduct(existingProduct);
        Review savedReview = reviewRepository.save(review);

        return mapToDto(savedReview);
    }


    public List<ReviewDto> findAll(long productId) {
        Product existingProduct = productRepository.findById(productId).orElseThrow(() -> new RuntimeException("Product with id: " + productId + " was  not found"));
        List<Review> reviewList = reviewRepository.findByProductId(productId);
        List<ReviewDto> reviewDtoList = new ArrayList<>();

        for (Review review : reviewList) {
            reviewDtoList.add(mapToDto(review));
        }
        return reviewDtoList;
    }

    public ReviewDto findById(long productId, long reviewId) {
        Product existingProduct = productRepository.findById(productId).orElseThrow(() -> new RuntimeException("Product with id: " + productId + " not found"));
        Review existingReview = reviewRepository.findById(reviewId).orElseThrow(() -> new RuntimeException("Review with id: " + reviewId + " not found"));

        if (!((existingReview.getProduct().getId()) == (existingReview.getId()))) {
            throw new RuntimeException("Product with id: " + productId + " doesn't correspond to review with id: " + reviewId);
        }
        return modelMapper.map(existingReview, ReviewDto.class);
    }

    public ReviewDto update(long productId, long reviwId, ReviewDto reviewDto) {

        Product existingProduct = productRepository.findById(productId).orElseThrow(() -> new RuntimeException("Product with id: " + productId + " not found"));
        Review existingReview = reviewRepository.findById(reviwId).orElseThrow(() -> new RuntimeException("Review with id: " + reviwId + " not found"));

        if (!(existingReview.getProduct().getId() == (existingProduct.getId()))) {
            throw new RuntimeException("Review with id " + reviwId + " does not belong to product with id " + productId);
        }

        existingReview.setEmail(reviewDto.getEmail());
        existingReview.setDescription(reviewDto.getDescription());

        Review savedReview = reviewRepository.save(existingReview);

        return mapToDto(savedReview);

    }

    public void delete(long productId, long reviewId) {
        Product existingProduct = productRepository.findById(productId).orElseThrow(() -> new RuntimeException("Product with id: " + productId + " not found"));
        Review existingReview = reviewRepository.findById(reviewId).orElseThrow(() -> new RuntimeException("Review with id: " + reviewId + " not found"));

        if (!(existingReview.getProduct().getId() == (existingProduct.getId()))) {
            throw new RuntimeException("Review with id " + reviewId + " does not belong to product with id " + productId);
        }
        reviewRepository.delete(existingReview);

    }


    private Review mapToEntity(ReviewDto reviewDto) {

        Review review = new Review();
        review.setId(reviewDto.getId());
        review.setEmail(reviewDto.getEmail());
        review.setDescription(reviewDto.getDescription());

        return review;
    }

    private ReviewDto mapToDto(Review review) {

        ReviewDto reviewDto = new ReviewDto();
        reviewDto.setId(review.getId());
        reviewDto.setEmail(review.getEmail());
        reviewDto.setDescription(review.getDescription());

        return reviewDto;
    }
}