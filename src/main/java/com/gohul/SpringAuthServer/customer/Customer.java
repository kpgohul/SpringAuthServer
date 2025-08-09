package com.gohul.SpringAuthServer.customer;


import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "customers")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Builder
@EntityListeners(AuditingEntityListener.class)
public class Customer {

    @Id
    private Long customerId;
    private String username;
    private String email;
    private String password;
    private Long mobileNumber;
    @JsonIgnore
    @CreatedDate
    @Column(updatable = false, nullable = false)
    private LocalDateTime createdAt;
}
