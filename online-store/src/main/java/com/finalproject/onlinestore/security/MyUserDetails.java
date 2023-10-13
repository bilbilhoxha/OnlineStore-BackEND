package com.finalproject.onlinestore.security;

import com.finalproject.onlinestore.entity.Role;
import com.finalproject.onlinestore.entity.User;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@AllArgsConstructor
public class MyUserDetails implements UserDetails {

    // The user for which the UserDetails is created
    private User user;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<Role> roles = user.getRoles();

        // Create a list of SimpleGrantedAuthority for each role

        //Set<SimpleGrantedAuthority> simpleGrantedAuthoritySet = new HashSet<>();
        List<SimpleGrantedAuthority> simpleGrantedAuthorityList = new ArrayList<>();
        for (Role role:roles) {
            simpleGrantedAuthorityList.add(new SimpleGrantedAuthority(role.getRole()));
        }
        return simpleGrantedAuthorityList;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
