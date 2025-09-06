# srun.sh
pure shell script to login srun
纯粹的shell实现深澜系统的登录（除了使用curl openssl）

本项目借鉴自karin0/sdusrun 与 SadPencil/sdunetd
在山东大学中心校区完成实验

学长们的项目都很好，但是有个问题，都需要编译为二进制文件。
出于两个方向考虑：

1. 冷门平台的工具链问题
2. 嵌入式编译操作繁琐

基于相关协议实现纯shell实现的登录器，仅仅依赖于必要的组件（curl和openssl，这两个组件在我的openwrt系统中都有）,保证在极限环境中的登录实现。

同时也将考试支持html版本和vbs版本。

##  环境要求
在运行此脚本之前，请确保你的系统上安装了以下命令行工具。这些工具在绝大多数系统中都是预装的。

bash

curl

openssl (用于 MD5-HMAC 加密)

标准的 GNU Coreutils: grep, sed, cut, tr, od, head, date 等。
