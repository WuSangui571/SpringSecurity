package com.sangui.springsecurity.controller;


import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.CircleCaptcha;
import cn.hutool.captcha.ICaptcha;
import com.sangui.springsecurity.captcha.MyCodeGenerate;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-22
 * @Description: 验证码的 Controller
 * @Version: 1.0
 */
@RestController
public class CaptchaController {
    // 这是个生成验证码的 Controller，不需要跳转页面，所以返回值是 void，就是把生成的图片以流的方式显示在前端浏览器上
    @RequestMapping(value = "/common/captcha",method = RequestMethod.GET)
    public void generateCaptcha(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 1.设置该请求相应的类型是图像
        response.setContentType("image/jpeg");

        // 2. 生成图片
        // 生成默认的图像（即既带字母，又带数字）90 × 30，验证码长度为 4，干扰圆圈 50个，字体大小为 1 倍的图像高度
        // ICaptcha captcha = CaptchaUtil.createCircleCaptcha(90, 30, 4, 50,1);

        // 2. 生成图片
        // 生成自定义的图像，90 × 30，验证码长度为 4，干扰圆圈 50个
        //ICaptcha captcha = CaptchaUtil.createCircleCaptcha(90, 30, new MyCodeGenerate(), 50);

        // 2. 生成图片
        // 生成 GIF 动态图片
        ICaptcha captcha = CaptchaUtil.createGifCaptcha(90, 30, new MyCodeGenerate(), 50);

        // 3. 把图片里面的验证码字符串在后端保存起来，因为后续前端提交的验证码需要验证
        request.getSession().setAttribute("captcha", captcha.getCode());
        System.out.println(captcha.getCode());

        // 4.把生成的验证码图片以 I/O 流的方式显示到前端浏览器上
        captcha.write(response.getOutputStream());
    }
}
