#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: nestealin
# Created: 2021-08-21

import log
import logging
import conf
import json
import ssl
import sys
import socket
import platform
import time
from datetime import datetime


def check_domain_valid(domain):
    for symbol in conf.abnormal_symbol:
        if symbol in domain:
            logging.error("输入的域名存在异常符号，正在退出...")
            sys.exit(1)

    return domain


def check_expire(domain_left_days_info_list, expire_date, shown_status=False):
    """
    :param domain_left_days_info_list: <list> [<str>, <str>, <int>] ['域名', '远程主机', 剩余天数]
    :param expire_date: <int> 自定检测的剩余天数阈值
    :param shown_status: <int> 显示状态(True显示执行, False隐藏)
    :return: <list> ['域名: xxx，远程主机: xxx, 还剩 d 天到期']
    """

    almost_expire_list = list()
    if shown_status is True:
        logging.info(
            '正在检测域名:%s, 远程主机:%s的证书过期时间...' %
            (domain_left_days_info_list[0],
             domain_left_days_info_list[1]))
    if domain_left_days_info_list[2] < expire_date:
        almost_expire_list.append(
            '域名:%s, 远程主机:%s, 还剩 %d 天到期' %
            (domain_left_days_info_list[0],
             domain_left_days_info_list[1],
             domain_left_days_info_list[2]))
    return almost_expire_list


def local_domain_list_init(domain_list_file=conf.domain_list_file_path):
    logging.info('开始从%s文件读取待检测域名...' % domain_list_file)
    domain_list = list()
    for domain in open('%s' % domain_list_file, 'r').readlines():
        domain = domain.strip('\n')

        if domain.startswith('#') or len(domain) < 3:
            logging.warning('该行内容 "%s" 被注释或为空，跳过检测' % domain)
        else:
            domain = check_domain_valid(domain)
            domain_list.append(domain)
    return domain_list


def get_domain_remote_host(domain):
    try:
        myaddr = socket.getaddrinfo(domain, None)
        if myaddr:
            return 200, myaddr[0][4][0]
        else:
            return 1508, "域名%s解析结果为空" % domain
    except Exception as e:
        logging.error("域名%s解析远程主机异常:%s" % (domain, str(repr(e))))
        return 1507, "域名%s解析存在异常" % domain


def ssl_socket(servername, remote_server=None, shown_status=False, **kwargs):
    """
    :param servername: <str> test1.baidu.com
    :param remote_server: <str> 可选，用于指定域名hosts访问，留空默认跟着本机域名解析执行
    :param shown_status: <bool> 可选，具体域名证书内容
    :param kwargs: <dict> 可选，{"line": "默认"} || {"type": "CNAME"}
    :return: <tuple> 正常(<int>, <list>) || 异常(<int>, <str>)
    """

    if remote_server is None:
        remote_host = get_domain_remote_host(servername)
    else:
        remote_host = [200, remote_server]

    domain_line = kwargs.get("line", "None(直接查询无该值记录)")
    domain_type = kwargs.get("type", "None(直接查询无该值记录)")

    try:

        if remote_host[0] == 200:
            logging.info(
                "正在检测域名:%s, 远程主机:%s的SSL证书详情..." %
                (servername, remote_host[1]))
            ctx = ssl.create_default_context()
            client = socket.socket()
            # 设置5秒连接超时
            client.settimeout(5)
            # 指定远程https端口为443
            with ctx.wrap_socket(client, server_hostname=servername) as ssl_client:
                ssl_client.connect((remote_host[1], 443))

                cert_info = ssl_client.getpeercert()
                """
                # 证书KEY信息:
                subject
                issuer
                version
                serialNumber
                notBefore
                notAfter
                subjectAltName
                OCSP
                caIssuers
                crlDistributionPoints
                """

                # 证书包含域名(SAN)
                subject_alt_name_list = cert_info["subjectAltName"]
                cert_dns_dict = dict()
                cert_dns_dict["DNS"] = dns_list = list()
                for cert_dns in subject_alt_name_list:
                    dns_list.append(cert_dns[1])
                # print(cert_dns_dict)

                # 证书主体详情，部分包含主体名称，个人可能只有“commonName”
                subject = dict(x[0] for x in cert_info["subject"])
                logging.debug("证书主体详情如下:\n%s" % json.dumps(subject))

                # 证书主体
                # cert_subject = subject["organizationName"]

                # 证书主域
                # issued_to = subject["commonName"]

                issuer = dict(x[0] for x in cert_info["issuer"])
                logging.debug("证书签发机构详情如下:\n%s" % json.dumps(issuer))
                # 签发机构
                issued_by = issuer["organizationName"]

                # 签发时间
                start_date = cert_info["notBefore"]

                # 过期时间
                expire_date = cert_info["notAfter"]

                # 计算证书有效期剩余天数
                check_datetime = datetime.now()
                # 切割天数的取值范围可能因时间格式不对导致无法转换，例如[-25:-5]时会出现如下报错
                # ValueError("time data 'Sep 17 11:18:16 202' does not match format '%b %d %H:%M:%S %Y'")
                expire_datetime = datetime.strptime(
                    expire_date[-25:-4], "%b %d %H:%M:%S %Y")
                left_days = (expire_datetime - check_datetime).days

                domain_left_days_list = list()
                domain_left_days_list.append(servername)
                domain_left_days_list.append(remote_host[1])
                domain_left_days_list.append(left_days)

                if shown_status is True:
                    logging.info(
                        '域名(Domain): {servername}'.format(
                            servername=servername))
                    logging.info(
                        '线路(Line): {domain_line}'.format(
                            domain_line=domain_line))
                    logging.info(
                        '记录类型(Domain Type): {domain_type}'.format(
                            domain_type=domain_type))
                    logging.info(
                        '记录解析/值(Domain Value): {domain_value}'.format(
                            domain_value=remote_host[1]))
                    logging.info(
                        '颁发时间(notBefore): {start_date}'.format(
                            start_date=start_date))
                    logging.info(
                        '过期时间(notAfter): {expire_date}'.format(
                            expire_date=expire_date))
                    logging.info(
                        '剩余时间(Days left): {left_days} 天'.format(
                            left_days=left_days))
                    logging.info(
                        '签发机构(Issuer): {issuer_name}'.format(
                            issuer_name=issued_by))
                    logging.info(
                        '证书包含域名(subjectAltName): {subjectAltName}'.format(
                            subjectAltName=', '.join(
                                cert_dns_dict.get("DNS"))))
                logging.info(conf.split_line*55)

            return 200, domain_left_days_list
        else:
            return 1509, remote_host[1]

    except socket.timeout as s_timeout:
        err_msg = "域名: %s, 远程主机: %s, error: %s" % (
            servername, remote_host[1], s_timeout)
        logging.error(
            "域名%s到目标主机%s连接超时，详情:%s" %
            (servername, remote_host[1], err_msg))
        return 1505, err_msg

    except ssl.CertificateError as cert_error:
        err_msg = "域名: %s, 远程主机: %s, error: %s" % (
            servername, remote_host[1], cert_error.verify_message)
        err_no = cert_error.verify_code

        if err_no == 10:
            logging.error("域名%s证书已过期，详情:%s" % (servername, err_msg))
            return 1504, err_msg
        elif err_no == 62:
            logging.error(
                "目标站点%s证书与域名%s不匹配，详情:%s" %
                (remote_host[1], servername, err_msg))
            return 1503, err_msg
        else:
            return 1511, err_msg

    except OSError as os_err:
        err_msg = "域名: %s, 远程主机: %s, error: %s" % (
            servername, remote_host[1], os_err.strerror)
        err_no = os_err.errno

        if err_no == 61:
            logging.error(
                "域名%s的远程主机%s连接被拒绝，详情:%s" %
                (servername, remote_host[1], err_msg))
            return 1502, err_msg
        else:
            return 1510, err_msg

    # 提前兜socket或者证书报错可能会混淆具体原因
    except Exception as e:
        err_msg = "域名: %s, 远程主机: %s, error: %s" % (
            servername, remote_host[1], str(repr(e)))
        logging.error(
            "域名:%s，远程主机:%s存在其他异常: %s" %
            (servername, remote_host[1], err_msg))
        return 1501, err_msg


def detect_to_single_domain(domain: str, shown_status=False):

    single_domain_status_dict = conf.detect_status_dict

    ssl_cert_info = ssl_socket(domain, shown_status=shown_status)
    if ssl_cert_info[0] == 200:
        expire_list = check_expire(ssl_cert_info[1], conf.detect_expire_date)
        if expire_list:
            single_domain_status_dict[1500]["details"].append(expire_list[0])
        else:
            single_domain_status_dict[200]["details"].append(domain)
    else:
        single_domain_status_dict[ssl_cert_info[0]
                                  ]["details"].append(ssl_cert_info[1])

    return single_domain_status_dict


def detect_from_local_domain_file(domain_list, shown_status=False):

    local_domain_list_status_dict = conf.detect_status_dict

    for domain in domain_list:
        ssl_cert_info = ssl_socket(domain, shown_status=shown_status)
        if ssl_cert_info[0] == 200:
            expire_list = check_expire(
                ssl_cert_info[1], conf.detect_expire_date)
            if expire_list:
                local_domain_list_status_dict[1500]["details"].append(
                    expire_list[0])
            else:
                local_domain_list_status_dict[200]["details"].append(domain)
        else:
            local_domain_list_status_dict[ssl_cert_info[0]]["details"].append(
                ssl_cert_info[1])
    return local_domain_list_status_dict


def detect_result_output(status_dict):
    logging.info("\n{split_line}\n检测结束, 详细结果如下:\n{split_line}".format(split_line=conf.split_line*20))
    for status_code in status_dict:
        msg = "发现%d个域名%s, 详情如下:\n%s" % (len(
            status_dict[status_code]["details"]),
            status_dict[status_code]["description"],
            '\n'.join(
            status_dict[status_code]["details"]))

        if len(status_dict[status_code]["details"]) == 0:
            logging.info(
                "本次未检测到域名存在%s状态，跳过输出..." %
                status_dict[status_code]["description"])

        elif len(status_dict[status_code]["details"]) > 0 and status_code == 200:
            logging.info(msg)

        elif len(status_dict[status_code]["details"]) > 0 and status_code == 1500:
            logging.warning(msg)

        else:
            logging.error(msg)


def input_options(shown_status=False):
    welcome_msg = '''{split_line}
温馨提醒:
1) 本脚本默认检查{expire_date}天内过期域名, 如需修改阈值, 请在"conf.py"中修改"detect_expire_date"字段
2) "本地域名列表检测" 需要提前在当前目录下"{domain_list_file}"文件中提前编写, 详情可参考"domain.sample"文件
{split_line}
本脚本可提供如下检测操作:
1. 单域名检测
2. 根据本地域名列表检测
3. 退出'''.format(split_line=conf.split_line*12, expire_date=conf.detect_expire_date, domain_list_file=conf.domain_list_file_path)

    print(welcome_msg)

    option_1 = input('请输入操作序号: ')
    if option_1.isdigit():
        if int(option_1) == 1:
            domain = input('请输入检测域名(例如:www.baidu.com): ').replace(" ", "")
            domain = check_domain_valid(domain)
            single_status_dict = detect_to_single_domain(
                domain, shown_status=shown_status)
            detect_result_output(single_status_dict)

        elif int(option_1) == 2:
            domain_list = local_domain_list_init()
            local_domain_status_dict = detect_from_local_domain_file(
                domain_list, shown_status=shown_status)
            detect_result_output(local_domain_status_dict)

        elif int(option_1) == 3:
            logging.info('正在退出...')
            sys.exit(0)

        else:
            logging.error('请按上述提示输入对应操作序号。')
            sys.exit(1)
    else:
        logging.error('请按上述提示输入对应操作序号。')
        sys.exit(1)


if __name__ == '__main__':

    if platform.python_version().split('.')[0] < '3':
        logging.error(
            '温馨提示:当前版本为%s , 请使用python3环境运行此脚本。' %
            platform.python_version())
        sys.exit()

    # shown_status可控制是否输出具体的证书信息
    input_options(shown_status=True)

