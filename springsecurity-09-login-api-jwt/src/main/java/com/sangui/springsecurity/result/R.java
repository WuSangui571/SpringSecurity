package com.sangui.springsecurity.result;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-26
 * @Description: 后端使用 R 对象,封装返回给前端,这样后端返回的数据结构就统一了
 * @Version: 1.0
 */
@Slf4j
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class R {
    // 结果码
    private Integer code;

    // 结果信息(成功了,还是失败了)
    private String msg;

    // 结果类型数据(可能是 String,也可能是 user 对象等)
    private Object data;

    /**
     * 默认成功的对象
     * @return R 对象
     */
    private static R ok() {
        return R.builder().code(200).msg("成功").data(null).build();
    }

    /**
     * 成功的对象(可写结果码和结果信息)
     * @param msg 成功的结果信息
     * @return R 对象
     */
    public static R ok(String msg) {
        return R.builder().code(200).msg(msg).data(null).build();
    }

    /**
     * 成功的对象(可写结果类型数据)
     * @param msg 成功的结果信息
     * @param data 结果类型数据
     * @return R 对象
     */
    public static R ok(String msg,Object data) {
        return R.builder().code(200).msg(msg).data(data).build();
    }

    /**
     * 默认失败的对象
     * @return R 对象
     */
    public static R fail() {
        return R.builder().code(500).msg("失败").data(null).build();
    }

    /**
     * 失败的对象(可写结果信息)
     * @param msg 失败的结果信息
     * @return R 对象
     */
    public static R fail(String msg) {
        return R.builder().code(500).msg(msg).data(null).build();
    }

    /**
     * 失败的对象(可写结果码和结果信息)
     * @param msg 失败的结果信息
     * @param data 结果类型数据
     * @return R 对象
     */
    public static R fail(String msg,Object data) {
        return R.builder().code(500).msg(msg).data(data).build();
    }

}
