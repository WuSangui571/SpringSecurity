package com.sangui.springsecurity;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class CaptchaLoginApplicationTests {

    @Test
    void test01() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String encode1 = passwordEncoder.encode("123");
        System.out.println(encode1); // $2a$10$EGCBc7Ly4uHJOUW/lVxaJO2nmyWbgKo2zjRXP8EV0UlXvtiCVgEhq
        String encode2 = passwordEncoder.encode("123");
        System.out.println(encode2); // $2a$10$1CNG7b9KnKf9iF5bqHH90uY5MuG3TXaMB6eP8ipb03X.2YMhsVS4a
        String encode3 = passwordEncoder.encode("123");
        System.out.println(encode3); // $2a$10$aHV.uyeQRBoXfRk/9NCnvOlIZH0zMsEIYleilaHU0.M..dJogzDbW
        System.out.println(passwordEncoder.matches("123", encode1)); // true
        System.out.println(passwordEncoder.matches("123", encode2)); // true
        System.out.println(passwordEncoder.matches("123", encode3)); // true

        System.out.println(encode1.length());
    }

}
