#!/bin/python3
# -*- coding: utf-8 -*-
# Author: nestealin
# Created: 2019-09-29

import os
import datetime
import log
import logging.config

'''
参考链接:
https://blog.csdn.net/zs_2014/article/details/45602243
https://cloud.tencent.com/developer/section/1369394
输出格式模板(formatter)参数参考:
%(levelno)s：打印日志级别的数值。
%(levelname)s：打印日志级别的名称。
%(pathname)s：打印当前执行程序的路径，其实就是sys.argv[0]。
%(filename)s：打印当前执行程序名。
%(funcName)s：打印日志的当前函数。
%(lineno)d：打印日志的当前行号。
%(asctime)s：打印日志的时间。
%(thread)d：打印线程ID。
%(threadName)s：打印线程名称。
%(process)d：打印进程ID。
%(processName)s：打印线程名称。
%(module)s：打印模块名称。
%(message)s：打印日志信息。

引用方法:
与程序同级目录下:
# 引入本路径的log文件必须连上logging一并引入或from log import *
import log
import logging
'''


# 定义日志输出文件夹路径,此处为脚本当前目录的logs文件夹内,若不存在则会自动创建
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)  # 创建路径
# 定义日志输出文件名
LOG_FILE_NAME = datetime.datetime.now().strftime("%Y-%m-%d") + ".log"

LOGGING = {
    # 版本，只能是1
    "version": 1,
    "disable_existing_loggers": False,
    # 定义日志输出模板
    "formatters": {
        "stander_formatter": {
            # 定义日志输出格式“[2019-09-28 23:39:00.456] static_resources_deploy.py[line:538] ERROR error test”
            'format': '[%(asctime)s.%(msecs)03d] %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
            # 格式化日志时间
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'thread_print_formatter': {
            'format': '%(asctime)s [%(threadName)s:%(thread)d] [%(name)s:%(lineno)d] [%(levelname)s]=>%(message)s'
        },
    },
    # 定义输出类型,可定义多种,最终选择需要的再输出也可
    "handlers": {
        # 定义屏幕输出
        "console": {
            # 定义一个StreamHandler，将日志输出到控制台
            "class": "logging.StreamHandler",
            "level": "INFO",
            # 控制台套用“stander_formatter”日志格式
            "formatter": "stander_formatter",
            "stream": "ext://sys.stdout"
        },
        # 定义日志文件输出
        "logfile": {
            # 输出类型为文件
            "class": "logging.handlers.RotatingFileHandler",
            # 定义输出等级,超过INFO及以上等级将被记录到文件
            "level": "INFO",
            # 定义日志输出格式模板,与上方formatters关联
            "formatter": "stander_formatter",
            # 定义日志输出的文件路径及文件名
            "filename": os.path.join(LOG_DIR, LOG_FILE_NAME),
            'mode': 'w+',
            # 定义文件切割大小值,当超过50M时,就会对旧文件增加后缀为“.1”“.2”等,保存旧文件数量由backCount参数指定
            "maxBytes": 1024 * 1024 * 50,  # 50 MB
            # 指定保留10个切割日志文件
            "backupCount": 10,
            # 定义文件编码模式 utf-8
            "encoding": "utf8"
        },
    },
    "root": {
        # 定义需要输出的模式,与上方handlers配置关联,指定则输出
        'handlers': ['console', 'logfile'],
        # 定义日志总体输出等级,最低可输出DEBUG等级(此为输出下限,若调整为ERROR,则控制台或文件最低只能显示ERROR级日志信息)
        'level': "DEBUG",
        'propagate': False
    }
}

# 使用LOGGING配置文件实现日志参数自定义
logging.config.dictConfig(LOGGING)
