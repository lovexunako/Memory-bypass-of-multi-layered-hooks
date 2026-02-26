# Memory-bypass-of-multi-layered-hooks
基于多层hook流的免杀
此程序只能用于网络安全研究，请勿非法使用



Hook（钩子）是一种拦截和修改程序或系统正常行为的技术。在免杀中，Hook用于篡改API调用，让安全软件看到的是“假象”，而恶意代码可以正常执行。是高级免杀技术的核心组成部分




[启动阶段]
    ↓
main() 
    ↓
反沙箱检测 ──进程数≤60?──→ 退出
    ↓ (通过)
安装7层API钩子
    ↓
调用Sleep(1000) 触发钩子
    ↓
[HookedSleep 触发链]
    ↓
临时恢复Sleep
    ↓
DownloadAndExecuteShellcode()
    ↓
    ├─ Base64解码URL
    ├─ HookedInternetOpenA (伪装UA)
    ├─ HookedInternetOpenUrlA (添加HTTP头)
    ├─ HookedInternetReadFile (读取数据)
    ├─ Base64解码shellcode
    ├─ HookedVirtualAlloc (分配RW内存)
    ├─ memcpy复制shellcode
    ├─ VirtualProtect (改RX权限)
    └─ HookedCreateThread (隐藏线程执行)
    ↓
重新安装Sleep钩子
    ↓
无限等待 (进程常驻)







7层API钩子链：同时钩住Sleep、VirtualAlloc、CreateThread、InternetOpenA等关键API
内存权限控制：RWX→RW+RX两步分配，绕过内存扫描
网络流量伪装：User-Agent和HTTP头模拟正常浏览器
反沙箱检测：基于进程数的运行环境判断
Base64混淆：URL和载荷双重编码




此代码配合AI参与 
国内杀软全免


喜欢的话请点点star 谢谢师傅
