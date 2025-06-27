package com.sangui.springsecurity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sangui.springsecurity.model.TUser;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Base64;

@SpringBootTest
class LoginApiApplicationTests {

	// 在 Test 注解里简单模拟 jwt 的生成
//	@Test
//	void testJwt() throws Exception {
//		// 这里是用户自己选择的
//		String alg = "HS256";
//		Object object = new TUser();
//
//		// 从以下代码开始就是自己执行的
//
//		// 假设这里的 JWT_SECRET 就是本项目的一个静态变量密钥
//		String secret = JWT_SECRET;
//
//		String headerJson = "{\"alg\": \"" + alg + "\",\"typ\": \"JWT\"}";
//		String payloadJson = new ObjectMapper().writeValueAsString(object);
//
//		// 假设这里的 base64UrlEncode 方法就是我们的 Base64URL  加密算法。
//		String headerEncoded   = base64UrlEncode(headerJson);
//		String payloadEncoded  = base64UrlEncode(payloadJson);
//
//		// 假设这里的 HMACSHA256 方法就是我们的 HMAC SHA256 加密算法。
//		String signature  = HMACSHA256(headerEncoded   + "." + payloadEncoded ,secret);
//
//		// 这就是最终的 jwt 字符串了
//		String jwt  = headerEncoded   + "." +  payloadEncoded  + "." + signature;
//	}

}
