package com.gohul.SpringAuthServer.config;


import com.gohul.SpringAuthServer.customer.Customer;
import com.gohul.SpringAuthServer.customer.CustomerRepo;
import com.gohul.SpringAuthServer.customer.CustomerRoles;
import com.gohul.SpringAuthServer.customer.RolesRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final CustomerRepo repo;
    private final RolesRepo cusRoleRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Customer customer = repo.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User details not found with email::" + username));
        List<CustomerRoles> rolesList = cusRoleRepo.findByCustomer(customer);
        var roles = rolesList.stream()
                .map(authZ -> new SimpleGrantedAuthority(authZ.getRole())).toList();
        return new User(customer.getEmail(), customer.getPassword(), roles);

    }
}
