#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include <string.h>

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，检查项包括：版本号、总长度、首部长度等。
 * 
 *        接着，计算头部校验和，注意：需要先把头部校验和字段缓存起来，再将校验和字段清零，
 *        调用checksum16()函数计算头部检验和，比较计算的结果与之前缓存的校验和是否一致，
 *        如果不一致，则不处理该数据报。
 * 
 *        检查收到的数据包的目的IP地址是否为本机的IP地址，只处理目的IP为本机的数据报。
 * 
 *        检查IP报头的协议字段：
 *        如果是ICMP协议，则去掉IP头部，发送给ICMP协议层处理
 *        如果是UDP协议，则去掉IP头部，发送给UDP协议层处理
 *        如果是本实验中不支持的其他协议，则需要调用icmp_unreachable()函数回送一个ICMP协议不可达的报文。
 *          
 * @param buf 要处理的包
 */
void ip_in(buf_t *buf)
{
    // TODO 
    struct ip_hdr * ip_buf = (struct ip_hdr *)buf;
    //报头检查
    if(ip_buf->hdr_len < 5 &&
    ip_buf->version != 4 && ip_buf->version != 6 &&
    ip_buf->total_len < swap16(20)){
        printf("incorrect header\n");
        return;
    }
    uint16_t checknum = checksum16((uint16_t *)buf,10); //调用 checksum函数来计算头部校验和
    if(ip_buf->hdr_checksum != swap16(checknum)){
        printf("incorrect checksum\n");
        return;
    }
    //对比目的 IP 地址是否为本机的 IP 地址
    if(memcmp(ip_buf->dest_ip,net_if_ip,sizeof(net_if_ip))!=0){
        printf("incorrect ip\n");
        return;
    }
    //调用 buf_remove_header 去掉 IP 报头
    uint8_t src_ip[4];
    memcpy(src_ip,ip_buf->src_ip,sizeof(src_ip));
    if(ip_buf->protocol == NET_PROTOCOL_UDP){
        buf_remove_header(buf,20);
        udp_in(buf,src_ip);
    }
    else if(ip_buf->protocol == NET_PROTOCOL_ICMP){
        buf_remove_header(buf,20);
        icmp_in(buf,src_ip);
    }
    else{ //不能识别的协议类型，调用 icmp_unreachable 返回 ICMP 协议不可达信息。
        icmp_unreachable(buf,ip_buf->src_ip,ICMP_CODE_PROTOCOL_UNREACH);
    }

}

/**
 * @brief 处理一个要发送的ip分片
 *        你需要调用buf_add_header增加IP数据报头部缓存空间。
 *        填写IP数据报头部字段。
 *        将checksum字段填0，再调用checksum16()函数计算校验和，并将计算后的结果填写到checksum字段中。
 *        将封装后的IP数据报发送到arp层。
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TODO
    
}

/**
 * @brief 处理一个要发送的ip数据包
 *        你首先需要检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - 以太网报头长度）。
 *        
 *        如果超过，则需要分片发送。 
 *        分片步骤：
 *        （1）调用buf_init()函数初始化buf，长度为以太网帧的最大包长（1500字节 - 以太网报头长度）
 *        （2）将数据报截断，每个截断后的包长度 = 以太网帧的最大包长，调用ip_fragment_out()函数发送出去
 *        （3）如果截断后最后的一个分片小于或等于以太网帧的最大包长，
 *             调用buf_init()函数初始化buf，长度为该分片大小，再调用ip_fragment_out()函数发送出去
 *             注意：id为IP数据报的分片标识，从0开始编号，每增加一个分片，自加1。最后一个分片的MF = 0
 *    
 *        如果没有超过以太网帧的最大包长，则直接调用调用ip_fragment_out()函数发送出去。
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TODO 
    // 检查从上层传递下来的数据报包长是否大于以太网帧的最大包长1500-14
    struct ip_hdr * ip_buf = (struct ip_hdr *)buf;
    struct ip_hdr ip_head;
    memcpy(&ip_head,buf,sizeof(ip_head));
    //如果超过以太网帧的最大包长，则需要分片发送
    if(ip_buf->total_len > ETHERNET_MTU-14){
        buf_t * new_buf;
        int piece_num = (ip_buf->total_len%(ETHERNET_MTU-14)==0)?
        ip_buf->total_len/(ETHERNET_MTU-14):ip_buf->total_len/(ETHERNET_MTU-14)+1;
        
    }


}
