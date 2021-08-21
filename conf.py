#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: nestealin
# Created: 2021/08/21

split_line = "="

abnormal_symbol = ["/", ":"]

# 域名列表检测文件
domain_list_file_path = "./meta_domain_data/domain.conf"

# 检测过期最小天数阈值
detect_expire_date = 30

# 用于判断检测的域名类型
domain_type = ["CNAME", "A"]

# 处理状态码
detect_status_dict = {
    # 域名正常，不会在检测阈值时间内过期
    200: {"description": "正常域名", "details": list()},
    1500: {"description": "证书即将过期", "details": list()},
    1501: {"description": "其他错误", "details": list()},
    1502: {"description": "连接拒绝", "details": list()},
    1503: {"description": "与证书域名不匹配", "details": list()},
    1504: {"description": "证书已过期", "details": list()},
    1505: {"description": "连接超时", "details": list()},
    1506: {"description": "根域id获取失败", "details": list()},
    1507: {"description": "dns解析存在其他错误", "details": list()},
    1508: {"description": "域名解析异常", "details": list()},
    1509: {"description": "远程主机解析异常", "details": list()},
    1510: {"description": "远程主机SSL连接异常", "details": list()},
    1511: {"description": "证书存在其他异常", "details": list()},
}

