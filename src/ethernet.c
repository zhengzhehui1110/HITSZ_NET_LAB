#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 处理一个收到的数据包
 *        你需要判断以太网数据帧的协议类型，注意大小端转换
 *        如果是ARP协议数据包，则去掉以太网包头，发送到arp层处理arp_in()
 *        如果是IP协议数据包，则去掉以太网包头，发送到IP层处理ip_in()
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TODO
    
    if (buf->data[12] == 0x08 && buf->data[13] == 0x00){ //IP
        buf_remove_header(buf,14);
        ip_in(buf);
    }
    else if (buf->data[12]==0x08 && buf->data[13]==0x06){ //ARP
        buf_remove_header(buf,14);
        arp_in(buf);
    }

    
}

/**
 * @brief 处理一个要发送的数据包
 *        你需添加以太网包头，填写目的MAC地址、源MAC地址、协议类型
 *        添加完成后将以太网数据帧发送到驱动层
 * 
 * @param buf 要处理的数据包
 * @param mac 目标ip地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TODO
    buf_add_header(buf,14);
    buf->data[0] = mac[0];
    buf->data[1] = mac[1];
    buf->data[2] = mac[2];
    buf->data[3] = mac[3];
    buf->data[4] = mac[4];
    buf->data[5] = mac[5];

    buf->data[6] = 0x11;
    buf->data[7] = 0x22;
    buf->data[8] = 0x33;
    buf->data[9] = 0x44;
    buf->data[10] = 0x55;
    buf->data[11] = 0x66;

    buf->data[12] = protocol / 0x100;
    buf->data[13] = protocol & 0x00ff;
    
    driver_send(buf);
}

/**
 * @brief 初始化以太网协议
 * 
 * @return int 成功为0，失败为-1
 */
int ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MTU + sizeof(ether_hdr_t));
    return driver_open();
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
