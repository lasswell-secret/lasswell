# MiniSM2_C

这是一个 C 语言教学型 SM2 项目，使用 SM2 推荐椭圆曲线参数，实现了：

- 256 位整数模运算
- SM3 杂凑算法
- 椭圆曲线点加、倍点、标量乘法
- SM2 密钥生成
- SM2 加密与解密
- SM2 签名与验签
- 加密速率测试

项目不依赖 OpenSSL、GMP 等第三方开源库。代码只使用 C 标准库和 MinGW GCC 可用的 `__uint128_t` 扩展。

## 目录

```text
MiniSM2_C/
  include/          头文件
  src/              主实现代码
  test/             简单测试程序
  build.bat         编译演示程序
  build_test.bat    编译测试程序
```

## 编译运行

在 Windows PowerShell 或 cmd 中进入项目目录：

```bat
build.bat
MiniSM2.exe
```

也可以指定加密速率测试轮数：

```bat
MiniSM2.exe 10
```

编译并运行测试：

```bat
build_test.bat
test_sm2.exe
```

## 说明

`src/benchmark.c` 中的 `benchmark_sm2_encrypt` 会重复执行 SM2 加密。主程序默认使用 1024 字节消息测试，输出：

- 测试轮数
- 单条消息长度
- 总耗时
- 每秒加密次数
- 明文吞吐量 KiB/s

本项目主要用于课程设计和算法原理演示。`util_random_bytes` 使用 C 标准库 `rand()` 生成演示随机数，不适合真实安全系统。真实密码系统应使用合规安全随机源，并使用经过安全审计的密码库。
