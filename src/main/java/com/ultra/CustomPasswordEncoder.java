package com.ultra;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.math.BigInteger;
import java.security.MessageDigest;

public class CustomPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence rawPassword) {
        try {
            //给数据进行md5加密
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(rawPassword.toString().getBytes());
            String pwd = new BigInteger(1, md.digest()).toString(16);
            System.out.println("encode方法：加密前（" + rawPassword + "），加密后（" + pwd + "）");
            return pwd;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // 判断密码是否存在
        if (rawPassword == null) {
            return false;
        }
        //通过md5加密后的密码
        String pass = this.encode(rawPassword);
        System.out.println("matches方法：rawPassword：" + rawPassword + "，encodedPassword：" + encodedPassword + "，pass：" + pass);
        //比较密码是否相等的问题
        return pass.equals(encodedPassword);
    }
}
