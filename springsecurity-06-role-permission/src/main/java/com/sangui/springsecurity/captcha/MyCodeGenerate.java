package com.sangui.springsecurity.captcha;


import cn.hutool.captcha.generator.CodeGenerator;

import java.util.Random;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-22
 * @Description: 我的自定义验证码生成器（四位随机数字）
 * @Version: 1.0
 */
public class MyCodeGenerate implements CodeGenerator {
    private static final Random RANDOM = new Random();
    private static final int CODE_LENGTH = 4;
    private static final char[] NUMBER_POOL = "0123456789".toCharArray();

    @Override
    public String generate() {
        StringBuilder sb = new StringBuilder(CODE_LENGTH);
        for (int i = 0; i < CODE_LENGTH; i++) {
            sb.append(NUMBER_POOL[RANDOM.nextInt(NUMBER_POOL.length)]);
        }
        return sb.toString();
    }

    @Override
    public boolean verify(String code, String userInputCode) {
        return false;
    }
}
