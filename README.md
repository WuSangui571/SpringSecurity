学习SpringSecurity

+ 开始时间：2025-06-20

### 第 1 章 SpringSecurity 基础

创建SpringBoot 项目，且需要引入 SpringBoot、SpringSecurity 依赖，Controller 控制器代码只 Mapping 一个 /hello 的 uri 的方法。

启动项目之后访问 http://localhost:8080/hello ，并不会跳转到此地址，而是会自动跳转到 http://localhost:8080/login，需输入账号密码才能继续访问原地址，账号默认为 user，密码是后端输出的临时密码，点击 Sign in 按钮之后，才会继续访问原 http://localhost:8080/hello 地址。

登录之后，在不关闭浏览器的情况下，再次重新访问 http://localhost:8080/hello ，不会再跳转至登录页面，浏览器会“记住我“，可以直接访问 /hello。

SpringSecurity 是通过基于 Session 机制，采用 Filter（16个 Filter）进行过滤拦截的，SpringBoot 项目里有内嵌的 Tomcat，登录之后，这个 Tomcat 会创建 Session，这个 Session 和前端的 SESSIONID 是绑定的。浏览器的开发者模式中可以找到这个 SESSIONID ，通过这个 SESSIONID，可以找到内嵌的 Tomcat 里的 Session，通过这个就能判断你有没有登录。

SpringSecurity 自动生成 的 /login 页面是通过 框架的 DefaultLoginPageGeneratingFilter （类似这种类有 16 个）这个类自动生成的， 他会根据用户是否登录来选择创建 /login 这个页面

另外，SpringSecurity 框架还提供退出页面，uri 是 /logout，是通过 DefaultLogoutPageGeneratingFilter 这个类自动生成的，点击这个生成页面的 `Log Out`  按钮，立即退出登录并跳转到 http://localhost:8080/login

在 SpringBoot 的配置文件中可以额外配置 SpringSecurity 的自定义账号密码，通过查看框架中的 SecurityProperties 这个类，可以清楚得看到，默认用户名是 user，password 是自动生成的（password = UUID.randomUUID().toString()），可以在我们的 application.yml 中修改配置，类似：

```yaml
spring:
  security:
    user:
      name: sangui
      password: your-password
```

但是，正常是不会通过配置文件来配置账号密码的，而是会选择使用数据库中的数据来登录。

### 第 2 章 通过数据库中的数据来登录 SpringSecurity

选择 MySQL 来实现通过数据库中的信息登录。准备一个 t_user 表，该表中至少有两个字段，login_act，login_pwd，即至少包含账户名，密码。

+ MyBatis 部分

  选择 MyBatis 框架作为 SpringBoot 项目的持久层框架

  + 创建 实体类 TUser 类

  + 创建 Mapper 接口 TUserMapper 类

    注意，该接口中至少要写一个根据用户名（login_act）查找实体类（TUser）的接口方法

  + 创建 mapper 映射文件 TUserMapper.xml 

    注意，至少写一个对应 TUserMapper  接口中的根据用户名查找实体类的 SQL 语句

  + 增加配置信息

    添加数据库，MyBatis 的配置信息，比如：

    ```yaml
    spring:
      datasource:
        username: your-database-username
        password: your-database-password
        driver-class-name: com.mysql.cj.jdbc.Driver
        url: jdbc:mysql://localhost:3306/your-database-name
    mybatis:
      mapper-locations: classpath:/mappers/*.xml
    ```

+ Service 部分

  + 创建 UserService 接口

    注意，该接口必须继承了 UserDetailsService 这个接口。需要在UserService 的实现类中重写 UserDetailsService 接口的 loadUserByUsername 方法。

  + 创建 UserServiceImpl 类

    注意，该类中必须需要重写 UserDetailsService 接口的 loadUserByUsername 方法。这个方法的返回值类型是 UserDetails，这个返回的类是个接口，使用 SpringSecurity 框架的 User 类作为实现类，这个接口中只有三个必要的 getXxx 方法，其他都有默认值先暂时不用管（有四个默认值，是关于账号是否有效的 Boolean 类型的）。这三个方法是：getUsername、getPassword、getAuthorities。所以说，要确定这个方法的返回对象，只需要确定这三个值就可，即 username、password、authorities ，前两个容易理解，是账号密码，第三个是权限，先不管，先暂时设为空。

    所以说，这个 UserServiceImpl  类到底该怎么写？

    这个类只需要重写 loadUserByUsername(String username) 方法即可，该方法中，先通过 tUserMapper 来查询数据库中对应 username 的字段信息整合成 Java 实体类，若找不到，则抛出 SpringSecurity 提供的 UsernameNotFoundException 异常。找到之后，构建 UserDetails 对象返回即可，构建这个对象的实例代码如下：

    ```java
    // 构建一个 SpringSecurity 框架里提供的 UserDetails 对象来返回
    UserDetails userDetails = User.builder()
            .username(tUser.getLoginAct())
            .password(tUser.getLoginPwd())
            // 权限先暂时设为空
            .authorities(AuthorityUtils.NO_AUTHORITIES)
            .build();
    ```
    
    注意，上面代码里的 User 不是我们的实体类，而是 SpringSecurity 框架的 User 类

+ Controller 部分

  创建 uri 为 "/hello" 的一个欢迎界面方法即可。

  通过上一章的讲解可以得出，若用户已登录，会访问 http://localhost:8080/hello 的欢迎界面。若用户未登录，会访问 http://localhost:8080/login 的自动登录界面。

至此，看起来整个程序已经完整了，试着运行这个程序，但是发现这个程序还不能运行，后端运行后部分提示如下：

```
Given that there is no default password encoder configured, each password must have a password encoding prefix. Please either prefix this password with '{noop}' or set a default password encoder in `DelegatingPasswordEncoder`.
```

说是缺少了默认的密码加密器，说明此时，应该添加密码加密器程序才能运行。我们通常用的加密器是 SpringSecurity框架自己提供的 BCryptPasswordEncoder 。这时，我们应该额外写一个配置类，即和在 ssm 中的 spring-context.xml 文件中配置 bean 的作用一样的配置类。

+ 配置类部分

  创建一个 SecurityConfig 配置类，将 SpringSecurity 中的 BCrypt 加密器引入我们的 IoC 容器之中该方法中只需要写如下内容。

  ```java
  @Bean
  public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
  }
  ```

  因为 PasswordEncoder 类是 SpringSecurity 框架自己的类，我们不能在框架的类上标注 @Resource 注解来纳入我们自己的 IoC 容器，所以额外写了@Bean 这个注解方法，方法返回这个类的构造方法。 上面代码的内容，相当于 xml 文件中写：（但我们现在是不会选择使用 xml 文件的）

  ```xml
  <bean id="passwordEncoder" class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"/>
  ```

+ 通过数据库中的数据来登录流程总结分析

  1. 访问 http://localhost:8080/hello

  2. 被 SpringSecurity 的 filter 拦截（里面有 16 个 Filter）

  3. 由于我没有登录过，所以 SpringSecurity 就跳转到登录页（登录页是框架生成的）
  
  4. 我们在登录页输入**账号**和**密码**去提交登录（账号密码来自数据库）
  
  5. SpringSecurity里面的 UsernamePasswordAuthenticationFilter 接受账号和密码

  6. 第 5 步的这个 filter 会调用 loadUserByUsername(String username) 方法通过去数据库查询用户
  
  7. 从数据库查询到用户后，把用户组装成 UserDetail 对象，然后返回给 SpringSecurity 框架
  
  8. 第 7 步返回后，会到框架的 AbstractUserDetailsAuthenticationProvider 内部 DefaultXXXAuthenticationChecks 类的 check() 方法进行用户状态的判断，用户对象中默认有 4 个状态 Boolean 字段，如果这 4 个状态字段的值都是 true，该用户才能登录，否则就是提示用户状态不正常，不能登录的）
  
  9. 第7步返回后，再回到框架的 DaoAuthenticationProvider 类的 additionalAuthenticationChecks() 方法进行密码的匹配，如果密码匹配上了，就登录成功，否则失败
  
  10. 比较密码的代码
  
      ```java
      String presentedPassword = authentication.getCredentials().toString();
      if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
          this.logger.debug("Failed to authenticate since password does not match stored value");
          throw new BadCredentialsException(this.messages
              .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
      }
      ```
  
      userDetails 对象是存放密文密码的用户类，authentication 对象是存放明文密码的用户类。上述程序就出现了加密器
  

### 第 3 章 SpringSecurity 使用自定义登录页

这一章的程序会在第 2 章程序的基础上进行修改，因为大致程序都相同，只是把登录页从它框架自动生成的，换成是自己的登录页。

我们选择使用 Thymeleaf 模板的前端登录页。

我们只需要在配置类中配置 SecurityFilterChain 这个类，就可以将登录页换成自己的登录页，比如：

```java
@Bean
public SecurityFilterChain securityFilterChain() {
	return new DefaultSecurityFilterChain(参数...);
}
```

但我们一般不会这么 new 一个对象的，而是采用方法参数注入 HttpSecurity 的形式：

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
	return httpSecurity
                // 配置自己的登录页
                .formLogin((formLogin) ->{
                    // 定制登录页 (Thymeleaf 页面)
                    formLogin.loginPage("/toLogin");
                })
        
        		.build();
}
```

暂时先假设我们的登录页路径为 "/toLogin"。

此时我们需要创建一个自定义登录页面，并将其绑定到这个 "/toLogin" 路径。其中自定义页面如下：（我们先设置 "/user/login" 为表单提交路径）

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Login Page</title>
</head>
<body>
    <form action="/user/login" method="post">
        账号：<input type="text" name="username"><br/>
        密码：<input type="password" name="password"><br/>
        <input type="submit" value="Login">
    </form>
</body>
</html>
```

接着再在 Controller 中将这个页面绑定我们的路径：（注意我们的 Controller 类上的注解不能是 @RestController，只能是 @Controller，因为这里返回的是模板页面 ）

```java
@RequestMapping(value = "/toLogin",method = RequestMethod.GET)
public String toLogin(){
    return "login";
}
```

至此，看起来我们的程序已经完备了，我的逻辑是：访问 http://localhost:8080/hello ，若用户未登录，会自动 http://localhost:8080/toLogin 的登录界面，若用户已登录，会继续访问 http://localhost:8080/hello 的欢迎界面。于是我开始测试，发现我未登录，也能访问到欢迎页面，断点调试程序发现框架根本就没有拦截，这是怎么回事？

原因是当你配置了 SecurityFilterChain 这个类之后，SpringSecurity 框架的某些行为就弄丢了（失效了），此时你需要加回来

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
	return httpSecurity
                .formLogin((formLogin) ->{
                    formLogin.loginPage("/toLogin");
                })
        
        		// 把所有接口都会进行登录状态检查的默认行为，再加回来
        		.authorizeHttpRequests((authorizeHttpRequests) -> {
        			// 任何对后端接口的请求，都需要认证（登录）后才能访问
        			authorizeHttpRequests.anyRequest().authenticated();
        		}
                                       
        		.build();
}
```

至此，看起来我们的程序已经完备了，于是我开始测试，访问 http://localhost:8080/hello，发现确实可以跳转到 http://localhost:8080/toLogin 页面，但是网页显示**该网站无法正常运作 localhost 将您重定向的次数过多**，哦，我才发现， 因为我任何请求我都选择需要认证，导致 http://localhost:8080/toLogin 这个请求他也需要认证，这是不合理的，我需要将登录页面排除在外。于是就有了：

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
	return httpSecurity
                .formLogin((formLogin) ->{
                    formLogin.loginPage("/toLogin");
                })
        
        		.authorizeHttpRequests((authorizeHttpRequests) -> {
        			authorizeHttpRequests
                            // 特殊情况设置，"/toLogin"页面允许访问
                            .requestMatchers("/toLogin").permitAll()
                            .anyRequest().authenticated();
        		}
                                       
        		.build();
}
```

至此，看起来我们的程序已经完备了，于是我开始测试，访问 http://localhost:8080/hello，发现确实可以跳转到 http://localhost:8080/toLogin 页面，这个页面页正常渲染显示了，但是呢，我输入正确的账号密码，点击登录按钮，并没有正确跳转登录成功，而是没有任何反应。这是怎么回事？

观察原本自动生成的 /login 页面，它的表单提交中，还会提交一个 hidden 隐藏域，于是我们也给他加进来

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Login Page</title>
</head>
<body>
    <form action="/user/login" method="post">
        账号：<input type="text" name="username"><br/>
        密码:<input type="password" name="password"><br/>
        <!--加入 hidden 的隐藏域，value 的值使用 thymeleaf 的语法确定-->
        <input type="hidden" name="_csrf" th:value="${_csrf.token}">
        <input type="submit" value="Login">
    </form>
</body>
</html>
```

这个隐藏域的值，SpringSecurity 框架会自动生成，我们只需要将他显示出来就行了，把他传入表单提交中就好，框架会通过 CsrfFilter 这个类，自动解析这个 token 是否正确。

至此，看起来我们的程序已经完备了，于是我开始测试，发现还是原来的问题，还是登录不上。这怎么解决？

原来还需要给 SpringSecurity 框架设置一个前端 form 表单提交的的一个路径，就是之前我们在前端写的 "/user/login" 路径：

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
	return httpSecurity
                .formLogin((formLogin) ->{
                    formLogin
                        	// 设置一个前端 form 表单提交的的一个路径
                            .loginProcessingUrl("/user/login")
                            .loginPage("/toLogin");
                })
        
        		.authorizeHttpRequests((authorizeHttpRequests) -> {
        			authorizeHttpRequests
                            .requestMatchers("/toLogin").permitAll()
                            .anyRequest().authenticated();
        		}
                                       
        		.build();
}
```

### 第 4 章 SpingSecurity 使用验证码登录

该章节程序要求：访问这个 web 程序时，要先通过前端的自定义页面输入用户名，密码，和匹配随机生成的验证码，才能登录访问本系统，

这一章的程序会在第 3 章程序的基础上进行修改，因为大致程序都相同，只是在登录的时候使用验证码进行登录。

首先要先更改前端页面：

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Login Page</title>
</head>
<body>
    <form action="/user/login" method="post">
        账号：<input type="text" name="username"><br/>
        密码:<input type="password" name="password"><br/>
        <!--前端添加验证码-->
        验证码：<input type="text" name="captcha"><img src="/common/captcha"><br/>
        <input type="hidden" name="_csrf" th:value="${_csrf.token}">
        <input type="submit" value="Login">
    </form>
</body>
</html>
```

前端随机生成的验证码图片的路径先定为： `/common/captcha` 。

由于自己写随机验证码图片过于困难和麻烦，这里通过使用 `hutool` 的依赖，靠它生成验证码。该工具建议仅在学习阶段使用，不建议在实际部署中使用（因为收购该工具的公司的风评不好，该公司近期更深陷于旗下另一开源项目 Alist 隐私困扰）：

```xml
<!-- https://mvnrepository.com/artifact/cn.hutool/hutool-captcha -->
<dependency>
    <groupId>cn.hutool</groupId>
    <artifactId>hutool-captcha</artifactId>
    <version>5.8.38</version>
</dependency>
```

接着写这个验证码的 Controller 类的代码，代码很简单，稍加看源码就能了解（源码的注释是中文）。

主要流程步骤如下：

1. 设置该请求类型（图像）
2. 生成图片
3. 保存验证码字符串
4. 将图片显示到前端上

```java
@RestController
public class CaptchaController {
    // 这是个生成验证码的 Controller，不需要跳转页面，所以返回值是 void，就是把生成的图片以流的方式显示在前端浏览器上
    @RequestMapping(value = "/common/captcha",method = RequestMethod.GET)
    public void generateCaptcha(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 1.设置该请求相应的类型是图像
        response.setContentType("image/gif");

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
        // 选择把后端生成的验证码放到 session 中
        request.getSession().setAttribute("captcha", captcha.getCode());
        System.out.println(captcha.getCode());

        // 4.把生成的验证码图片以 I/O 流的方式显示到前端浏览器上
        captcha.write(response.getOutputStream());
    }
}
```

这里我写的 Controller 其实并不规范，Controller 中一般只负责页面跳转，实际上的业务逻辑需要在 Service 包里写，我这里就为了方便省略了。

值得注意的是，这里可以自定义验证码生成规则，只需要按照 hutool 的规范创建它的一个自定义类就好，我定义的规则是生成的验证码是四位纯数字，代码如下：

```java
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
```

这个时候，我们启动服务访问浏览器发现，这个验证码的图片并不会显示出来，原因是我们之前的 SecurityConfig 类里的 SecurityFilterChain 方法设定了，如果未登录，只能访问 `/toLogin` 这个请求，我们的验证码请求是 `/common/captcha`，并不能访问，我们在这个方法中把这个路径补上就好，

```java
public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    // ...
    authorizeHttpRequests
            // 在这里加上我们允许为登录就访问就请求
            .requestMatchers("/toLogin","/common/captcha").permitAll()
            .anyRequest().authenticated();
    })
    // ...
}
```

紧接着，就是最重要的，创建这个验证码的过滤器，因为现在完全不能识别对应上我们刚才生成的验证码。但是，SpringSecurity框架并没有为验证码设计一个过滤器，所以这个过滤器需要我们自己写。

通过情况下，使用过滤器都会考虑到实现 servlet 的 Filter 接口这种方式，比如：

```java
public class CaptchaFilter implements Filter {
	@Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
		// ...
    }
}
```

但在 Spring 项目中，一般不会以这种方式使用，因为需要强转输入类型的参数，比较麻烦。我们更加倾向于选择继承 OncePerRequestFilter 类实现。继承这个抽象类，实际上也是在间接实现 servlet 的 Filter 接口，只不过继承这种方式不用转型，更加方便。

过滤器的逻辑很简单，就是只过滤登录请求，验证前后端的验证码是否匹配，若匹配上了，则用 filterChain.doFilter(request, response) 的方式放行，若没有匹配上，则跳转到 response.sendRedirect("/") ，此时别的过滤器会自动生效，自动跳转到登录页面（这里就忽略把验证未通过的 message 传到前端了，依然用 session 就好了），代码如下：

```java
@Component
public class CaptchaFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // captchaFromFront 是前端用户输入的验证码字符串
        String captchaFromFront = request.getParameter("captcha");

        // 如果是登录请求，就验证，否则不需要验证
        String requestURI = request.getRequestURI();
        if (!requestURI.equals("/user/login")){
            filterChain.doFilter(request, response);
            return;
        }
        if (!StringUtils.hasText(captchaFromFront)){
            // 前端传的验证码为空，验证未通过
            response.sendRedirect("/");
        }else if (!captchaFromFront.equalsIgnoreCase(request.getSession().getAttribute("captcha").toString())){
            // 两端验证码不相等，验证不通过
            response.sendRedirect("/");
        }else {
            // 通过！
            filterChain.doFilter(request, response);
        }
    }
}
```

注意加上 @Component 注解，因为现在 SpringBoot项目根本不会调用我们的过滤器，需要后续在配置文件中调用，所以我们要把这个类加入到 IoC 容器之中。

如何把我们写的过滤器加入这个责任链？

我们只需要在之前的 securityFilterChain 中的流式编程中添加上我们的过滤器就好，代码如下：

```java
public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    return httpSecurity
            .formLogin((formLogin) -> {
                formLogin
                        .loginProcessingUrl("/user/login")
                        .loginPage("/toLogin")
                    	// 后续测试发现的小 bug,要加上这一行，不然登录成功之后系统会自动跳转到原访问路径，原访问路径若找不到该资源，只能跳转到错误页面
                        .defaultSuccessUrl("/", true);
            })

            .authorizeHttpRequests((authorizeHttpRequests) -> {
                authorizeHttpRequests
                        .requestMatchers("/toLogin","/common/captcha").permitAll()
                        .anyRequest().authenticated();
            })

            // 在这里放我们的验证码过滤器，过滤器放在这个接受用户账号密码的 filter 之前
            .addFilterBefore(captchaFilter, UsernamePasswordAuthenticationFilter.class)

            .build();
}
```

接下来再进行一个大总结，总结下 SpringSecurity 验证码登录流程分析

1. 访问http://localhost:8080/hello 
2. 被 SpringSecurity 的 filter 过滤器拦截（里面有 16 个 Filter）
3. 由于没有登录过，所以 SpringSecurity  就跳转到自定义的登录页 login.html
4. 我们在登录页输入账号、密码、验证码 去提交登录
5. CaptchaFilter（我们写的）拦截登录请求，验证一下验证码对不对
6. 验证码正确，就执行下一个Filter，调用 UsernamePasswordAuthenticationFilter（Spring Security框架的）接收账号和密码
7. UserDetailsService.loadUserByUsername()（我们覆盖该方法）--> userMaper（mybatis）--> 查数据库 --> 返回 userDetail  (框架的)
8. 把 userDetail 返回给（框架）进行用户状态检查和密码比较

### 第 5 章 关于 BCrypt 密码加密和密码匹配原理

首先有个基本常识，就是在数据库中存储的并非密码的明文，而是存储由加密算法加密之后的密文（这也解释了，为什么市面上的几乎所有平台，你若忘记了密码，是会让你再重新创建一个新的密码，而不是把原密码给你，因为平台也不知道你的原密码明文究竟是多少）。这么做的好处就是若数据库信息被黑客泄露，也不会泄露最危险的明文密码。

目前比较流行的加密算法主要有两个，分别是 **MD5** 和 **BCrypt **，而我们的 SpringSecurity 框架默认是采用 **BCrypt **的。

之前的代码中，我们也使用过密码加密器，就是：

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

其中 PasswordEncoder 是密码加密接口，BCryptPasswordEncoder 是一个它的实现类。加密器最常用的两个方法是 **encode** 和 **matches**，即**加密**和**匹配**。注意，加密器是没有解密这个方法的，因为加密器也没有办法通过密文解密原文的。

然后，我试着写了些加密的代码，来进一步学习加密器：

```java
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
}
```

通过以上代码和输出结果，我得出一个结论：

即使是相同的明文，BCrypt 加密算法也会加密出不同的密文，同时，这些不同的密文，都能够和原文匹配。

接下来我将进一步解析 BCrypt  加密原理。

BCrypt  的加密原理是：

```
假设明文是 123，密文是 $2a$10$EGCBc7Ly4uHJOUW/lVxaJO2nmyWbgKo2zjRXP8EV0UlXvtiCVgEhq
```

+ 密文的 1 - 7 位
  + 密文的前七位字符是密文的版本，是固定的。
+ 密文的 8 - 29 位
  + 密文版本之后的 22 个字符，是加密算法随机生成的 22 位盐值（salt），这些盐值的不同就决定了我们重复加密同一个明文，密文却不一样的情况。

+ 密文的 30 - 60 位

  + 密文最后的 31 个字符，是通过算法生成的，参数就是明文和盐值，类似方法比如

    ```java
    String bcrypt(String mingwen,String salt){
    	// ...
    }
    ```

以上就是BCrypt  的大致加密原理，具体的 bcrypt 算法，就不在这里说了。至于匹配的原理也大致一样，匹配会依次找到密文的三个部分，版本，盐值和密文，根据上面的那个 bcrypt 方法得出的密文，和待匹配的密文进行比较，就可以得出匹配结果了。

### 第 6 章 SpringSecurity 获取当前登录用户的用户信息

该章节程序要求：当用户登录之后，可以在前台看到自己的登录账号的用户信息（其实就是登录的 t_user 表的所有字段值）

这一章的程序会在第 4 章程序的基础上进行修改，因为大致程序都相同，只是在登录后可以获取当前登录用户的用户信息。

有两种方法可以解决我们的本章要求，现在先将第一种，注入 jdk 的 Principal 接口

在我们的 Controller 类中加入如下代码：

```java
// 新增页面路径，访问这个页面，可以获取用户的所有具体信息（也就是用户表中有的字段的信息）
@RequestMapping(value = "/userInfo",method = RequestMethod.GET)
@ResponseBody
public Object userInfo(Principal principal){
    return principal;
}
```

我们先试着启动服务，登录后看访问这个路径会输出什么。

结果，我们发现，当登录后访问 http://localhost:8080/userInfo 时，浏览器出现以下内容：

```json
{
  "authorities": [],
  "details": {
    "remoteAddress": "0:0:0:0:0:0:0:1",
    "sessionId": "A1541A805A5A661A0D7E49F027C93D12"
  },
  "authenticated": true,
  "principal": {
    "password": null,
    "username": "admin",
    "authorities": [],
    "accountNonExpired": true,
    "accountNonLocked": true,
    "credentialsNonExpired": true,
    "enabled": true
  },
  "credentials": null,
  "name": "admin"
}
```

仔细观察这个 json 对象，发现有用的信息几乎没有，只有什么权限信息，ip，sessionId，只有我们可怜的 username 字段的 admin 这个值时才是我们觉得有用的，但这完全不够啊，我们的数据库中这张表的字段可不止这些啊。

这是为什么呢，是因为当初我们在 UserServiceImpl 类的 loadUserByUsername 方法里我们返回的用户信息对象是 SpringSecurity 框架自己的 user 对象，这是 SpringSecurity 框架早就写好的，框架根本无法预料到之后使用框架的人的用户表有什么字段，只能肯定一定有它所提供的一些必要字段（如，账号，密码，四种权限信息等），我们现在也无法改变框架的代码，所以该怎么办呢？

我们现在应该重新修改我的 TUser 实体类（就是对应我们数据库的实体表），让他实现 UserDetails 接口，我们就可以在 UserServiceImpl 类的 loadUserByUsername 方法里返回我们自己的 user 类了。

具体怎么做？TUser 类实现 UserDetails 接口，添加三个必要的方法（获取权限、获取密码、获取用户名），和四个非必要的方法（获取四个账户的是否过期的布尔值类型，非必须，不实现默认都不过期）。具体的添加的代码如下：

```java
@Data
public class TUser implements Serializable, UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 我们暂时不管返回什么权限，之后再学，先返回空
        // List.of()，实际上代表的就是返回空
        return List.of();
    }

    @Override
    public String getPassword() {
        // 返回我们的自己字段里的密码
        return this.loginPwd;
    }

    @Override
    public String getUsername() {
        // 返回我们的自己字段里的账户名
        return this.loginAct;
    }

    // 下面四个是非必要字段，不实现这四个方法，默认都不过期，即都是 true
    @Override
    public boolean isAccountNonExpired() {
        // accountNoExpired 是我数据库中的一个字段，用于显示账户是否没有过期，0已过期 1正常
        return this.accountNoExpired == 1;
    }

    @Override
    public boolean isAccountNonLocked() {
        // accountNoLocked 是我数据库中的一个字段，用于显示账号是否没有锁定，0已锁定 1正常
        return this.accountNoLocked == 1;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // credentialsNoExpired 是我数据库中的一个字段，用于显示密码是否没有过期，0已过期 1正常
        return this.credentialsNoExpired == 1;
    }

    @Override
    public boolean isEnabled() {
        // accountEnabled 是我数据库中的一个字段，用于显示账号是否启用，0禁用 1启用
        return this.accountEnabled == 1;
    }
    
    // 保留 TUser 类中原始的代码，上面的内容是新加的....
}
```

然后，就是在 UserServiceImpl 类的 loadUserByUsername 里，返回我们已经实现 UserDetails 接口的 TUser 类。具体代码如下：

```java
@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        TUser tUser = tUserMapper.selectByLoginAct(username);

        if (tUser == null) {
            throw new UsernameNotFoundException("登录账号不存在");
        }

        // 现在，我们就不需要以下的代码了！
//        UserDetails userDetails = User.builder()
//                .username(tUser.getLoginAct())
//                .password(tUser.getLoginPwd())
//                .authorities(AuthorityUtils.NO_AUTHORITIES)
//                .build();

		// 这里修改代码，返回我们自己的 tUser 对象
        return tUser;
    }
```

接下来，我们来看看启动服务，登陆后，浏览器会返回我们什么：

```json
{
  "authorities": [],
  "details": {
    "remoteAddress": "0:0:0:0:0:0:0:1",
    "sessionId": "4BCC47AE9CCE719F482D4CEE1BFA769B"
  },
  "authenticated": true,
  "principal": {
    "id": 1,
    "loginAct": "admin",
    "loginPwd": "$2a$10$Nlhwhtd0BSCBK95CAifv7eWpCjHloPBMZ3Gaehcc56hRAV3DZALJO",
    "name": "管理员",
    "phone": "13700000000",
    "email": "admin@qq.com",
    "accountNoExpired": 1,
    "credentialsNoExpired": 1,
    "accountNoLocked": 1,
    "accountEnabled": 1,
    "createTime": "2023-02-22T01:37:12.000+00:00",
    "createBy": null,
    "editTime": "2023-05-22T16:21:06.000+00:00",
    "editBy": null,
    "lastLoginTime": "2025-06-15T11:34:32.000+00:00",
    "enabled": true,
    "password": "$2a$10$Nlhwhtd0BSCBK95CAifv7eWpCjHloPBMZ3Gaehcc56hRAV3DZALJO",
    "credentialsNonExpired": true,
    "username": "admin",
    "accountNonExpired": true,
    "authorities": [],
    "accountNonLocked": true
  },
  "credentials": null,
  "name": "admin"
}
```

可以看到，这次返回的数据中，已经有我们的数据库中的字段值了。我们成功了。

但是，我也发现了一些问题，就是这段的 json 中的 principal 数组，是我们的数据库中的对应登录用户的数据，但是，它好像平白无故得多了几个字段，我一数，是最后七个字段：

```json
"enabled": true,
"password": "$2a$10$Nlhwhtd0BSCBK95CAifv7eWpCjHloPBMZ3Gaehcc56hRAV3DZALJO",
"credentialsNonExpired": true,
"username": "admin",
"accountNonExpired": true,
"authorities": [],
"accountNonLocked": true
```

即上面得七个，是我数据库中没有的，或者说是和我其他的字段有冲突的、重复的。这是这么回事，我好像在哪见过这些字段，就其实是在我们刚刚修改的 TUer 类里。

其实，这是一个正常现象，我们这个返回的 json 对象，是 SpringSecurity 框架通过的 jackson 这个 jar 包，由 java 对象（也就是我们的 tUser 对象）转化为的 json 对象，这个 jackson jar 包的转换，他会将我们类里的 getXxx方法，isYyy方法，自动转化为属性 xxx，yyy，不管你这个类里是否有这个 xxx，yyy 属性。这就解释了，为什么我们浏览器输出的 json 对象，会有这额外的七个字段了，因为 jackson 字段将我们刚刚修改的 TUser 类里的方法，识别成了我们类里的属性了。如何修复？很简单。只需要在不想输出的方法中加上 @JsonIgnore 注解 就可以了。就像：

```json
@Data
public class TUser implements Serializable, UserDetails {
    // 在这里加入 @JsonIgnore 注解，让 jackson 忽略生成这个属性
	@JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    // 在这里加入 @JsonIgnore 注解，让 jackson 忽略生成这个属性
	@JsonIgnore
    @Override
    public String getPassword() {
        return this.loginPwd;
    }

    // 在这里加入 @JsonIgnore 注解，让 jackson 忽略生成这个属性
	@JsonIgnore
    @Override
    public String getUsername() {
        return this.loginAct;
    }

    // 在这里加入 @JsonIgnore 注解，让 jackson 忽略生成这个属性
	@JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        
        return this.accountNoExpired == 1;
    }

    // 在这里加入 @JsonIgnore 注解，让 jackson 忽略生成这个属性
	@JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return this.accountNoLocked == 1;
    }

    // 在这里加入 @JsonIgnore 注解，让 jackson 忽略生成这个属性
	@JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNoExpired == 1;
    }

    // 在这里加入 @JsonIgnore 注解，让 jackson 忽略生成这个属性
	@JsonIgnore
    @Override
    public boolean isEnabled() {
        return this.accountEnabled == 1;
    }
    
    // 其他代码....
}
```

特别的，如果我们认为，不希望把一些属性返回到前端，比如我们的加密后的密码的字段，也可以为他加上 @JsonIgnore 注解，不让他传到前端：

```java
@JsonIgnore
private String loginPwd;
```

同样的，Date 类型的属性可以加这个注解，以返回前端正确的格式：@JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss",timezone = "GMT+8")，也可在 application.yml 文件中全局指定 jackson 返回的格式和时区，当然，这都不是现在 SpringSecurity 学习的重点，我就提一嘴。

现在，我们启动应用，登陆后，看到前端返回了：

```json
{
  "authorities": [],
  "details": {
    "remoteAddress": "0:0:0:0:0:0:0:1",
    "sessionId": "2F110AAE106F696C835F5D0B329CEE56"
  },
  "authenticated": true,
  "principal": {
    "id": 1,
    "loginAct": "admin",
    "loginPwd": "$2a$10$Nlhwhtd0BSCBK95CAifv7eWpCjHloPBMZ3Gaehcc56hRAV3DZALJO",
    "name": "管理员",
    "phone": "13700000000",
    "email": "admin@qq.com",
    "accountNoExpired": 1,
    "credentialsNoExpired": 1,
    "accountNoLocked": 1,
    "accountEnabled": 1,
    "createTime": "2023-02-22T01:37:12.000+00:00",
    "createBy": null,
    "editTime": "2023-05-22T16:21:06.000+00:00",
    "editBy": null,
    "lastLoginTime": "2025-06-15T11:34:32.000+00:00"
  },
  "credentials": null,
  "name": "admin"
}
```

这下子，principal 这个数组里返回的，就都是我们数据库中的字段了。

至此，我们获取当前登录用户的用户信息的第一种方法：注入 jdk 的 Principal 接口，就完成了。

第二种方法，使用 SpringSecurity 框架的 Authentication 接口，获取当前登录用户的用户信息。

实际上，这个 Authentication  接口就是继承了我们 jdk 提供的 Principal 接口，第二种方法，本质上还是第一种方法，只不过，我们在这种方法里，我们用的是 SpringSecurity 提供的接口了，而不是 jdk 提供的接口了。

同样的，我们在 Controller 这个类中加入新的页面：

```java
// 新增新的页面路径，这个路径使用的 SpringSecurity 框架提供的 Authentication 接口
// 今后最常用的就是 Authentication，不会用 Principal 的
@RequestMapping(value = "/userInfo2",method = RequestMethod.GET)
@ResponseBody
public Object userInfo2(Authentication authentication){
    return authentication;
}
```

其他程序都不用改，因为第二种方法和第一种方法就接口不一样，实际其实差不多的。

我们启动服务器，登录后跳转 http://localhost:8080/userInfo2 ,可以看到以下信息，这和第一种方法返回的一样

```json
{
  "authorities": [],
  "details": {
    "remoteAddress": "0:0:0:0:0:0:0:1",
    "sessionId": "F6F5A6F561B2DF5CB3089E2462AEB2F9"
  },
  "authenticated": true,
  "principal": {
    "id": 1,
    "loginAct": "admin",
    "loginPwd": "$2a$10$Nlhwhtd0BSCBK95CAifv7eWpCjHloPBMZ3Gaehcc56hRAV3DZALJO",
    "name": "管理员",
    "phone": "13700000000",
    "email": "admin@qq.com",
    "accountNoExpired": 1,
    "credentialsNoExpired": 1,
    "accountNoLocked": 1,
    "accountEnabled": 1,
    "createTime": "2023-02-22T01:37:12.000+00:00",
    "createBy": null,
    "editTime": "2023-05-22T16:21:06.000+00:00",
    "editBy": null,
    "lastLoginTime": "2025-06-15T11:34:32.000+00:00"
  },
  "credentials": null,
  "name": "admin"
}
```

至此，我们的两种方法就讲完了。甚至，我们还可以用 Authentication 接口的子接口 UsernamePasswordAuthenticationToken ，来实现第三种方式，只需要改Controller 类里的代码即可，就不再赘述了：

```java
@RequestMapping(value = "/userInfo3",method = RequestMethod.GET)
@ResponseBody
public Object userInfo3(UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken){
    return usernamePasswordAuthenticationToken;
}
```

甚至可以这样：（第四种方法）

```java
@RequestMapping(value = "/userInfo4",method = RequestMethod.GET)
@ResponseBody
public Object userInfo4(){
    return SecurityContextHolder.getContext().getAuthentication();
}
```

那我们平常在写程序时，我们通过会写个工具类，返回我们的已经登录用户的用户信息：

```java
public class LoginInfoUtil {
    private LoginInfoUtil(){}
    public static TUser getCurrentLoginUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return (TUser) authentication.getPrincipal();
    }
}
```

Controller 中则这样：

```java
@RequestMapping(value = "/userInfo5",method = RequestMethod.GET)
@ResponseBody
public Object userInfo5(){
    return LoginInfoUtil.getCurrentLoginUser().toString();
}
```

这样，我们登陆后，就可以获取已经登录的用户信息了，浏览器返回如下内容：

```json
{
  "id": 1,
  "loginAct": "admin",
  "loginPwd": "$2a$10$Nlhwhtd0BSCBK95CAifv7eWpCjHloPBMZ3Gaehcc56hRAV3DZALJO",
  "name": "管理员",
  "phone": "13700000000",
  "email": "admin@qq.com",
  "accountNoExpired": 1,
  "credentialsNoExpired": 1,
  "accountNoLocked": 1,
  "accountEnabled": 1,
  "createTime": "2023-02-22T01:37:12.000+00:00",
  "createBy": null,
  "editTime": "2023-05-22T16:21:06.000+00:00",
  "editBy": null,
  "lastLoginTime": "2025-06-15T11:34:32.000+00:00"
}
```

### 第 7 章 SpringSecurity 框架权限管理

SpringSecurity 框架权限管理基于两种，一种是基于角色的权限管理，还有一种是基于资源的权限管理。

现在先讲第一种，即基于角色的权限管理。

大致流程是：用户登录 -> 给用户配置角色 -> 给角色配置能访问的资源。具体来说就是先要有一个用户（从数据库中查询用户），再给用户配置角色（从数据库中查询用户的角色），最后就是给角色配置能访问的资源（这一步采用切面 aop 拦截，使用的是注解方式）

现在我一步一步说。

首先，要先有好的数据库表设计，业界非常经典的权限设计模型是创建五张表。分别是：t_user（用户表），t_role（角色表），t_permission（权限表），t_user_role（用户，角色的关联表），t_role_permission（角色，权限的关联表）。

+ t_user（用户表）

  这个用户表很好理解，就是存放用户数据的表

+ t_role（角色表）

  大部分角色表的有效字段就三个，只有 id，role，role_name，这三个字段，分别是自增id，角色（英文），角色（中文）

  该表很少增删改查，一般一开始就写好了各种角色，就算要改，也是后期添加角色

+ t_permission（权限表）

  权限表用于确认，不同的角色，能够具体有什么权限

  该表一般有以下几个字段，是id，name，code，url，type，parent_id，order_no，icon，下面详细介绍下：

  + id

    自增主键，不多说。

  + name

    具体权限的中文名字，比如：`用户管理`，`用户管理-列表`，`用户管理-xxx``用户管理-新增`，`用户管理-删除`，`交易管理`，`交易管理-新增`，`交易管理-更新`等等

  + code

    代码，规范点说叫做权限标识符，就是这个权限的代码，英文，可为空，比如：`user`，`user:list`，`user:add`，`user:delete`，`user:import`等等，code 字段可为空

  + url

    该权限访问对应的 url，url 字段可为空

  + type

    是什么类型的资源，比如：`menu`（菜单类型资源），`button`

  + parent_id

    父 id ，表示这个权限的父权限的 id。如已经是顶层了，用 0 表示。

  + order_no

    这是排序，在同一个父 id 下的排序才有意义，也就是说这个排序只是相对于同一个父 id 的排序，order_no 字段可为空

  + icon

    该权限的图标，当你的 type 是 menu 菜单时，才有图标，可为空

+ t_user_role（用户，角色的关联表）

  关联用户表和角色表主键的关联表，一般只有三个字段（自增id，用户表主键，角色表主键）

+ t_role_permission（角色，权限的关联表）

  关联角色表和权限表主键的关联表，一般只有三个字段（自增id，角色表主键，权限表主键）、

至此，前置的数据库要求已经完成了。

之前我说过，我们的流程是：用户登录 -> 给用户配置角色 -> 给角色配置能访问的资源。在前面六章的代码中，我们早就完成了用户登录，于是我们开始下一步：给用户配置角色。大致的想法就是：给我们的用户实体类添加一个权限的属性，再在用户的 Service 类里 loadUserByUsername 方法中，返回添加了权限属性的用户对象，下面来看具体实现：（注意先把 t_role 这个权限表的 MyBatis 三兄弟的代码自动生成好）

```java
public class TUser implements Serializable, UserDetails {
    /**
     * 单独添加的用户权限 List
     * 且该字段不希望能够 json 返回前端，添加 @JsonIgnore 注解
     */
    @JsonIgnore
    private List<TRole> tRoleList;

    /**
     * 我们现在要修改这个类，这个类不能再返回空列表了，而是返回由 tRoleList 封装的集合了
     * @return 用户权限集合
     */
    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 由于该方法要求的返回类型和我们自己的常规数据库返回类型 List 不同，所以我们需要转型
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        // 使用 for 循环放入我们新建的集合里
        for (TRole tRole : this.getTRoleList()){
            // SimpleGrantedAuthority 类是 GrantedAuthority 接口的具体实现类。
            authorities.add(new SimpleGrantedAuthority(tRole.getRole()));
        }
        return authorities;
    }
    // 其他别的代码......
}
```

下一步就是修改用户 Service 类的 loadUserByUsername 方法，把返回的用户对象的权限信息加上：

```java
@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        TUser tUser = tUserMapper.selectByLoginAct(username);

        if (tUser == null) {
            throw new UsernameNotFoundException("登录账号不存在");
        }


        // 在此处添加查询用户的角色信息列表（一个用户可能有多个角色）
        List<TRole> tRoleList = tRoleMapper.selectByUserId(tUser.getId());
        // 通过 set 方法写入我们的权限列表这个属性
        tUser.setTRoleList(tRoleList);

        return tUser;
    }
```

这下，我们的`给用户配置角色`，这一步流程就完成了，下一步：`给角色配置能访问的资源`。之前说过这一步采用切面 aop 拦截，使用的是注解方式。我们使用的权限拦截注解主要有两个：

+ PreAuthorize

  在方法调用前进行权限检查;（常用）

+ PostAuthorize

  在方法调用后进行权限检查;（很少用）

上面的两个注解如果要使用的话必须加上以下注解：（该注解一般放在 SpringSecurity 的配置类上）

```java
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    // ......
}
```

Controller 中的方法不加注解的，都可以访问，加了注解的，要有对应权限才可以访问。举个例子：

```java
@RestController
public class ClueController {
    /*
     * 举例，用户 id 为 3 的用户，ta 叫 zhangqi，拥有以下权限：
     * 线索管理
     * 线索管理
     * 线索管理-列表
     * 线索管理-录入
     * 线索管理-编辑
     * 线索管理-查看
     *
     * 没有以下权限：
     * 线索管理-删除
     * 线索管理-导出
     */

    // 这个方法的权限注解啥也不加，即没有权限验证
    @RequestMapping(value = "/api/index",method = RequestMethod.GET)
    public String index(){
        return "Index Page !";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/menu",method = RequestMethod.GET)
    public String clueMenu(){
        return "clueMenu";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/menu/child",method = RequestMethod.GET)
    public String clueMenuChild(){
        return "clueMenuChild";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/list",method = RequestMethod.GET)
    public String clueList(){
        return "clueList";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/input",method = RequestMethod.GET)
    public String clueInput(){
        return "clueInput";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/edit",method = RequestMethod.GET)
    public String clueEdit(){
        return "clueEdit";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/view",method = RequestMethod.GET)
    public String clueView(){
        return "clueView";
    }

    @PreAuthorize("hasAuthority('admin')")
    @RequestMapping(value = "/api/clue/del",method = RequestMethod.GET)
    public String clueDel(){
        return "clueDel";
    }

    // hasAnyRole注解，代表只有这些角色的其中一个就能通过
    @PreAuthorize("hasAnyAuthority('admin','manager')")
    @RequestMapping(value = "/api/clue/export",method = RequestMethod.GET)
    public String clueExport(){
        return "clueExport";
    }
}
```

注意到，我们的 @PreAuthorize 注解里写的是 `hasAnyAuthority()` 而不是 `hasRole()`，那么这两个有什么区别呢？

其实很简单，若你数据库中 t_role 表的 role 字段的值为类似 `admin` 的，用 hasAnyAuthority，而 role 字段的值为类似 `ROLE_admin` 的，用 hasRole。使用 hasRole 方法里的判断你的权限的值是带前缀 `ROLE_` 的，正常写的值得话，你就用 hasAnyAuthority 方法。

至此，SpringSecurity 框架的权限管理就完成了。

另外，我再提一个东西，就是，现在如果我们访问没有权限的页面，浏览器会自动跳转到默认的 403 页面，这个页面不是很好看，像是报错一样，我们现在可以使用自己定义一个 403 页面。

怎么做呢？很简单，我们的项目都有这个目录： `main/resource/static`，只需要在这个 `static` 目录下，新建一个目录，叫做 `error` 目录，这个页面下，放入我们自己的 403.html ，我们的项目就可以自动将 403 页面，替换为我们自己的页面了。

以上，就是我们的 SpringSecurity 框架的权限管理。当然了，我之前说过，SpringSecurity 框架权限管理基于两种，一种是基于角色的权限管理，还有一种是基于资源的权限管理。上面这种就是基于角色的权限管理。现在我们来讲另一种，基于资源的权限管理。其实他和基于角色差不多，只有一个小小的区别，就是到时候用的是权限 code 代码进行权限判断。下面我详细讲。

基于资源的权限管理也分为三步：用户登录（和之前一样，也是从数据库中查询用户） -> 给用户配置权限标识符（从数据库中查询用户的权限标志符，即权限 code） -> 给每个权限标志符配置能访问的资源（这一步还是切面拦截，使用的是注解），下面我说具体的详细步骤。

首先是修改用户表的实体类，添加权限 code 属性，删除角色属性，并把这个 code 属性方法到 getAuthorities 方法里：（注意先把 t_permission 这个权限表的 MyBatis 三兄弟的代码自动生成好）

```java
public class TUser implements Serializable, UserDetails {
    /**
     * 单独添加的用户权限标识符（权限 code） List
     * 且该字段不希望能够 json 返回前端，添加 @JsonIgnore 注解
     */
    @JsonIgnore
    private List<TPermission> tPermissionList;

    // 删掉之前的基于角色的权限管理字段
//    /**
//     * 单独添加的用户权限 List
//     * 且该字段不希望能够 json 返回前端，添加 @JsonIgnore 注解
//     */
//    @JsonIgnore
//    private List<TRole> tRoleList;

    /**
     * 修改之前的 getAuthorities 方法，改为放入 code 值
     * 在这里放入我们的权限 code
     * @return 用户权限集合
     */
    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        // 循环放入我们的 TPermission List 里的对象的 code 值
        for (TPermission tPermission : this.getTPermissionList()){
            // 这里放入具体的 code 值
            authorities.add(new SimpleGrantedAuthority(tPermission.getCode()));
        }
        return authorities;
    }
    // 其他代码......
```

然后修改用户 Service 类里的 loadUserByUsername 方法：

```java
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    TUser tUser = tUserMapper.selectByLoginAct(username);

    if (tUser == null) {
        throw new UsernameNotFoundException("登录账号不存在");
    }

    // 这是基于角色的权限管理代码，由于我们在测试基于资源的权限管理，所以先注解
//        // 在此处查询用户的角色信息列表（一个用户可能有多个角色）
//        List<TRole> tRoleList = tRoleMapper.selectByUserId(tUser.getId());
//        // 通过 set 方法写入我们的权限列表这个属性
//        tUser.setTRoleList(tRoleList);

    // 查询用户的权限 code 列表（一个用户可能有多个权限 code）
    List<TPermission> tPermissionList = tPermissionMapper.selectByUserId(tUser.getId());
    tUser.setTPermissionList(tPermissionList);

    return tUser;
}
```

下一步就是配置具体的 Controller 类了：

```java
@RestController
public class ClueController {
    /*
     * 举例，用户 id 为 3 的用户，他叫 zhangqi，拥有以下权限：
        线索管理-列表 -> clue:list
        线索管理-录入 -> clue:add
        线索管理-编辑 -> clue:edit
        线索管理-查看 -> clue:view
        线索管理-导入 -> clue:import
     */

    // 这个方法的权限注解啥也不加，即没有权限验证
    @RequestMapping(value = "/api/clue/index",method = RequestMethod.GET)
    public String index(){
        return "Index Page !";
    }

    @PreAuthorize("hasAuthority('clue:list')")
    @RequestMapping(value = "/api/clue/list",method = RequestMethod.GET)
    public String clueList(){
        return "clueList";
    }

    @PreAuthorize("hasAuthority('clue:add')")
    @RequestMapping(value = "/api/clue/add",method = RequestMethod.GET)
    public String clueAdd(){
        return "clueAdd";
    }

    @PreAuthorize("hasAuthority('clue:edit')")
    @RequestMapping(value = "/api/clue/edit",method = RequestMethod.GET)
    public String clueEdit(){
        return "clueEdit";
    }

    @PreAuthorize("hasAuthority('clue:view')")
    @RequestMapping(value = "/api/clue/view",method = RequestMethod.GET)
    public String clueView(){
        return "clueView";
    }

    @PreAuthorize("hasAuthority('clue:import')")
    @RequestMapping(value = "/api/clue/import",method = RequestMethod.GET)
    public String clueImport(){
        return "clueImport";
    }

    // 这是该用户没有的权限 code
    @PreAuthorize("hasAuthority('clue:del')")
    @RequestMapping(value = "/api/clue/del",method = RequestMethod.GET)
    public String clueDel(){
        return "clueDel";
    }

    // hasAnyAuthority 注解，代表只有这些 code 的其中一个就能通过
    @PreAuthorize("hasAnyAuthority('clue:xxx','clue:yyy')")
    @RequestMapping(value = "/api/clue/xxyy",method = RequestMethod.GET)
    public String clueExport(){
        return "clueExport";
    }
}
```

至此，就大功告成了，你看，其实步骤和之前的基于角色的权限管理几乎一模一样。

### 第 8 章 SpringSecurity 前后端分离登录认证

在前几章的例子中，我们是返回到 Thymeleaf 页面，但如果是前后端分离开发，是不能返回一个页面的，而应该是返回一个 JSON。

这时候，我们使用 Vue 作为我们这一章节的前端技术。注意：部署 Vue 要用到 Nginx 而 Nginx 无法和 后端部署的 Tomcat 共享 sesssion，这就相对于是两个项目了。此时，如何就需要处理我们登录的 session 问题。在这里，我们的前端的 Vue 页面我们这里先不写，先用简单的 HTML 页面代替，使用 Postman 工具测试接口。 

首先我们继承我们之前几章的代码，由于我们是前后端分离的项目，就可以把所以前端的页面都不要了，删了，把验证码模块先不用，权限管理模块也先不用，我们就验证下登录就好。

