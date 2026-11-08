# qianfen-heater-api
成都前锋热水器APP破解，使用API进行热水器设置


我使用一台红米手机，安装了termux,执行 heater_api_daemon.sh

1. 内部ESP32 通过GPIO监控接入米家的智能开关，输出内容如下 http://192.168.3.85/status
```shell
{
  "device": "ESP8266",
  "thinkStationActive": 0,
  "heaterActive": 0,
  "USER_2": 0,
  "USER_3": 0,
  "ledBlink": 1,
  "uptime": 18905
}
```
2. heater_api_deamon.sh 每100ms查看ESP32提供的HTTP是否触发热水器开关，进行启动零冷水功能

下一步优化，直接在ESP32上运行此功能，减少红米手机的参与