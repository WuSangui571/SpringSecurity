package com.sangui.springsecurity;

import jakarta.annotation.Resource;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;

/**
 * @author root
 */
@SpringBootApplication
@MapperScan("com.sangui.springsecurity.mapper")
public class JwtApplication implements CommandLineRunner {
	@Resource
	private RedisTemplate<String,Object> redisTemplate;

	/**
	 * 该 run 方法只在 SpringBoot 项目启动之后执行 1 次（就 1 次）
	 * 所有通常会在这个方法中写一些初始化工作
	 * @param args 参数
	 * @throws Exception 异常
	 */
	@Override
	public void run(String... args) throws Exception {
		// 这里我们配置 Redis 防止乱码的问题
		// 设置 Redis 的 Key 采用 string 进行序列化
		redisTemplate.setKeySerializer(RedisSerializer.string());
		// 设置 Redis 的 HashKey 采用 string 进行序列化
		redisTemplate.setHashKeySerializer(RedisSerializer.string());
		// 设置 Redis 的 HashValue 采用 string 进行序列化
		redisTemplate.setHashValueSerializer(RedisSerializer.string());
		// 设置 Redis 的 Value 采用 json 进行序列化
		// 若放入 Redis 的 Value 是一个对象，建议采用 json 序列化
		// redisTemplate.setValueSerializer(RedisSerializer.json());
	}

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

}
