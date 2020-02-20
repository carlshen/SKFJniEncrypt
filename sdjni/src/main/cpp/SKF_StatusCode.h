#ifndef SKF_STATUS_H
#define SKF_STATUS_H


#define SAR_OK                           0x00000000  //成功
#define SAR_FAIL                         0x0A000001  //失败
#define SAR_UNKNOWNERR                   0x0A000002  //异常错误
#define SAR_NOTSUPPORTYETERR             0x0A000003  //不支持的服务
#define SAR_FILEERR                      0x0A000004  //文件操作错误
#define SAR_INVALIDHANDLEERR             0x0A000005  //无效的句柄

#define SAR_READFILEERR                  0x0A000007  //读文件错误
#define SAR_WRITEFILEERR                 0x0A000008  //写文件错误

#define SAR_INDATALENERR                 0x0A000010  //输入数据长度错误
#define SAR_INDATAERR                    0x0A000011  //输入数据错误
#define SAR_GENRANDERR                   0x0A000012  //生成随机数错误

#define SAR_APPLICATION_EXISTS           0x0A00002C  //应用已经存在
#define SAR_APPLICATION_NOT_EXISTS       0x0A00002E  //应用不存在


#define SAR_BUFFER_TOO_SMALL             0x0A000020  //缓冲区不足
#define SAR_PIN_INCORRECT                0x0A000024  //PIN不正确
#define SAR_PIN_LOCKED                   0x0A000025  //PIN被锁死
#define SAR_PIN_INVALID                  0x0A000026  //PIN无效
#define SAR_PIN_LEN_RANGE                0x0A000027  //PIN长度错误
#define SAR_USER_TYPE_INVALID            0x0A00002A  //PIN类型错误
#define SAR_APPLICATION_NAME_INVALID     0x0A00002B  //应用名称无效
#define SAR_FILE_ALREADY_EXIST           0x0A00002F  //文件已经存在
#define SAR_NO_ROOM                      0x0A000030  //空间不足
#define SAR_FILE_NOT_EXIST               0x0A000031  //文件不存在


#define SECURE_NEVER_ACCOUNT             0x00000000  //不允许
#define SECURE_ADM_ACCOUNT               0x00000001  //管理员权限
#define SECURE_USER_ACCOUNT              0x00000010  //用户权限
#define SECURE_ANYONE_ACCOUNT            0x000000FF  //任何人权限

#endif //SKF_STATUS_H
