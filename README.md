# JavaMySqlDesCrypt
为了兼容改进旧项目，翻译的Java版mysql-des-encrypt和mysql-des-decrypt函数

## Java Code:
  - 加密示例：
    ```
    String key = "我们是地球人";
    String text = "广义的宇宙定义是万物的总称，是时间和空间的统一";
    byte[] res = MysqlCrypt.des_encrypt(text,key);
    System.out.println(Base64.getEncoder().encodeToString(res));
    ```
  - 解密示例:
    ```
    String key = "我们是地球人";
    String text = "//gO9rgAdmyqwI01A3d0O0D9BEZqbn+c7eMcpgybi3MTVI7rWCjj19XriQQ8nEi8k0uo0caCQs9F56Ga32C7z8dmE0WxPrkW7g==";
    byte[] res = MysqlCrypt.des_decrypt(Base64.getDecoder().decode(text),key);
    System.out.println(new String(res,"utf8"));
    ```
    
