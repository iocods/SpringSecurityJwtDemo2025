package io.iocodes.web.components;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class DemoController {

    private static final Logger log = LoggerFactory.getLogger(DemoController.class);

    @GetMapping("/hello")
    public String hello() {
        return "Hello, Welcome to Spring security integration with JWT and Redis 2025.!";
    }

    @GetMapping("/persons")
    public List<Person> demo() {
        Person person = Person.builder().name("John Doe").age(20).email("john@doe.com").build();
        return List.of(person);
    }

}