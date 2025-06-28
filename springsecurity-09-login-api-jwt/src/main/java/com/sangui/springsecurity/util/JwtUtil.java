package com.sangui.springsecurity.util;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-27
 * @Description: JWT 工具类
 * @Version: 1.0
 */
public class JwtUtil {
    // 密钥不能被别人知道
    public static final String SECRET = "sangui is MY sUPERhEROOOOOOO!!@#@#`$!@#!@%/^/&.(*^!,@#.!@#,$%^#$%";

    /**
     * 生成 JWT 字符串
     * @param userJson 由 user 对象的转化的 json 字符串
     * @return JWT 字符串
     */
    public static String createToken(String userJson) {
        // 组装头数据
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");
        return JWT.create()
                // 头
                .withHeader(header)
                // 自定义数据
                .withClaim("user", userJson)
                // 签名算法
                .sign(Algorithm.HMAC256(SECRET));
    }

    /**
     * 验证 JWT 是否被篡改过
     * @param token JWT 字符串
     * @return true 代表 JWT 没有被篡改过，false 代表 JWT 被篡改过
     */
    public static Boolean verifyToken(String token) {
        try {
            // 使用秘钥创建一个验证对象
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
            // 验证 JWT
            jwtVerifier.verify(token);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 解析 JWT 中的负载数据
     * @param token JWT 字符串
     * @return 解析 JWT，然后返回数据
     */
    public static String parseToken(String token) {
        try {
            // 使用秘钥创建一个解析对象
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
            //验证 JWT
            DecodedJWT decodedJwt = jwtVerifier.verify(token);
            Claim user = decodedJwt.getClaim("user");
            return user.asString();
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

}
