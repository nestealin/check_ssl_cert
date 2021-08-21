#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: nestealin
# Created: 2021/08/21

import OpenSSL
from dateutil import parser


def get_local_cert_info(cert_path: str):
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        open(cert_path).read())
    certIssue = cert.get_issuer()

    print("证书版本:            ", cert.get_version() + 1)
    print("证书主体:            ", cert.get_subject().O)
    print("证书域名:            ", cert.get_subject().CN)
    print("证书序列号:          ", hex(cert.get_serial_number()))

    print("证书中使用的签名算法:  ", cert.get_signature_algorithm().decode("UTF-8"))

    print("颁发者:             ", certIssue.commonName)

    datetime_struct = parser.parse(cert.get_notBefore().decode("UTF-8"))

    print("有效期从:            ", datetime_struct.strftime('%Y-%m-%d %H:%M:%S'))

    datetime_struct = parser.parse(cert.get_notAfter().decode("UTF-8"))

    print("到期时间:            ", datetime_struct.strftime('%Y-%m-%d %H:%M:%S'))

    print("证书是否已经过期:     ", cert.has_expired())

    print("公钥长度:            ", cert.get_pubkey().bits())

    print(
        "公钥:\n",
        OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_PEM,
            cert.get_pubkey()).decode("utf-8"))

    print("证书subject代表释义:")

    print("CN : 通用名称  OU : 机构单元名称")
    print("O  : 机构名    L  : 地理位置")
    print("S  : 州/省名   C  : 国名")

    for item in certIssue.get_components():
        print(item[0].decode("utf-8"), "  ——  ", item[1].decode("utf-8"))

    # 证书扩展字段，仅v3证书支持
    # print("ext:")
    # for ext_inx_num in range(cert.get_extension_count()):
    #     print(cert.get_extension(ext_inx_num))


if __name__ == '__main__':
    cert_path = "server.cer"
    get_local_cert_info(cert_path)

