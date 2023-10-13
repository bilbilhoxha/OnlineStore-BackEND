package com.finalproject.onlinestore.service;
import com.finalproject.onlinestore.dto.CategoryDto;
import com.finalproject.onlinestore.entity.Category;
import com.finalproject.onlinestore.repository.CategoryRepository;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class CategoryService {
    private CategoryRepository categoryRepository;
    private ModelMapper modelMapper;


    public CategoryDto save(CategoryDto categoryDto){
        Category category= modelMapper.map(categoryDto, Category.class);
        Category savedCategory= categoryRepository.save(category);

        return modelMapper.map(savedCategory, CategoryDto.class);
    }

    public List<CategoryDto> findAll(){
        List<Category> categoryList= categoryRepository.findAll();

        //return categoryList.stream().map((category)->modelMapper.map(category, CategoryDto.class));
        List<CategoryDto> categoryDtoList= new ArrayList<>();
        for( Category category: categoryList){
            modelMapper.map(category, CategoryDto.class);
        }
        return categoryDtoList;
    }

    public CategoryDto findById(long categoryId){

        //Category exCategory= categoryRepository.findById(categoryId).orElseThrow(()->new RuntimeException("Category with id "+ categoryId+" was not found"));
        Optional<Category> existingCategory= categoryRepository.findById(categoryId);

        if(existingCategory.isPresent()){
            return modelMapper.map(existingCategory.get(), CategoryDto.class);
        } else throw new RuntimeException("Category with id "+ categoryId+" was not found");
    }

    public CategoryDto update( CategoryDto categoryDto, long categoryId){
        Optional <Category> existingCategory = categoryRepository.findById(categoryId);
        if(existingCategory.isPresent()){
            existingCategory.get().setName(categoryDto.getName());
            existingCategory.get().setDescription(categoryDto.getDescription());

        } else throw new RuntimeException("Category with id "+ categoryId+" was not found");
        Category savedCategory= categoryRepository.save(existingCategory.get());

        return modelMapper.map(savedCategory,CategoryDto.class);
    }

    public void delete(long categoryId){
        Category existingCategory= categoryRepository.findById(categoryId).orElseThrow(()->new RuntimeException("Category with id "+ categoryId+" was not found"));
        categoryRepository.delete(existingCategory);
    }
}
