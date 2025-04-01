package io.iocodes.web.components;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Person {
    private long id;
    private String name;
    private int age;
    private String email;
}