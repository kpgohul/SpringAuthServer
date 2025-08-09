package com.gohul.SpringAuthServer.customer;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RolesRepo extends JpaRepository<CustomerRoles, Long> {
    boolean existsByRoleId(Long no);

    List<CustomerRoles> findByCustomer(Customer customer);
}
