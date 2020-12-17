#include "arp.h"
#include "utils.h"
#include "ethernet.h"
#include "config.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type = swap16(ARP_HW_ETHER),
    .pro_type = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = DRIVER_IF_IP,
    .sender_mac = DRIVER_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表
 * 
 */
arp_entry_t arp_table[ARP_MAX_ENTRY];

/**
 * @brief 长度为1的arp分组队列，当等待arp回复时暂存未发送的数据包
 * 
 */
arp_buf_t arp_buf;

/**
 * @brief 更新arp表
 *        你首先需要依次轮询检测ARP表中所有的ARP表项是否有超时，如果有超时，则将该表项的状态改为无效。
 *        接着，查看ARP表是否有无效的表项，如果有，则将arp_update()函数传递进来的新的IP、MAC信息插入到表中，
 *        并记录超时时间，更改表项的状态为有效。
 *        如果ARP表中没有无效的表项，则找到超时时间最长的一条表项，
 *        将arp_update()函数传递进来的新的IP、MAC信息替换该表项，并记录超时时间，设置表项的状态为有效。
 * 
 * @param ip ip地址
 * @param mac mac地址
 * @param state 表项的状态
 */
void arp_update(uint8_t *ip, uint8_t *mac, arp_state_t state)
{
    printf("\nupdate ip: %d %d %d %d",ip[0],ip[1],ip[2],ip[3]);//test
    printf("\nupdate mac: %x %x\n",mac[0],mac[1]);//test
    // TODO
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
    {
        if(time(NULL)-arp_table[i].timeout >= ARP_TIMEOUT_SEC){
            arp_table[i].state = ARP_INVALID; //ARP 表项是否有超时
        }
        
    }
    int flag = 0;
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
    {
        if (arp_table[i].state== ARP_INVALID) //查找 ARP 表项是否有 ARP_INVALID
        {
            //新的 ip、mac 信息插入到表中，记录超时时间，更改 state 状态
            memcpy(arp_table[i].ip,ip,sizeof(arp_table[i].ip));
            memcpy(arp_table[i].mac,mac,sizeof(arp_table[i].mac));
            arp_table[i].timeout = time(NULL);
            arp_table[i].state = ARP_VALID;
            flag = 1;
            //printf("here!!!!!!!!\n");
            break;
        }
    }
    if (flag == 0) // 如果 ARP 表中所有的表项都不是 ARP_INVALID
    {
        int to_be_del = 0;
        for (int i = 1; i < ARP_MAX_ENTRY; i++) //找到超时时间最长的一条表项
        {
            if(time(NULL)-arp_table[i].timeout > time(NULL)-arp_table[i-1].timeout)
                to_be_del = i;
        }
        memcpy(arp_table[to_be_del].ip,ip,sizeof(arp_table[to_be_del].ip));
        memcpy(arp_table[to_be_del].mac,mac,sizeof(arp_table[to_be_del].mac));
        arp_table[to_be_del].timeout = time(NULL);
        
    }
}

/**
 * @brief 从arp表中根据ip地址查找mac地址
 * 
 * @param ip 欲转换的ip地址
 * @return uint8_t* mac地址，未找到时为NULL
 */
static uint8_t *arp_lookup(uint8_t *ip)
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        if (arp_table[i].state == ARP_VALID && memcmp(arp_table[i].ip, ip, NET_IP_LEN) == 0)
            return arp_table[i].mac;
    return NULL;
}

/**
 * @brief 发送一个arp请求
 *        你需要调用buf_init对txbuf进行初始化
 *        填写ARP报头，将ARP的opcode设置为ARP_REQUEST，注意大小端转换
 *        将ARP数据报发送到ethernet层
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
uint8_t default_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
uint8_t bc_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
uint8_t my_ip[4] = {192, 168, 163, 103};
uint8_t all_zero_mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

static void arp_req(uint8_t *target_ip)
{
    // TODO
    //printf("target: %d %d\n",target_ip[0],target_ip[3]); //test
    buf_t txbuf;
    buf_init(&txbuf,sizeof(arp_pkt_t));
    arp_pkt_t *arp_head = (arp_pkt_t *)txbuf.data;
    //硬件类型
    memcpy(arp_head->sender_ip,my_ip,sizeof(my_ip));
    memcpy(arp_head->target_ip,target_ip,sizeof(my_ip));
    //arp_head->opcode = swap16(ARP_REQUEST);
    memcpy(arp_head->sender_mac,default_mac,sizeof(default_mac));
    memcpy(arp_head->target_mac,all_zero_mac,sizeof(all_zero_mac));

    arp_head->hw_type = swap16(ARP_HW_ETHER);
    //上层协议类型
    arp_head->pro_type = swap16(NET_PROTOCOL_IP);
    //MAC 地址长度
    arp_head->hw_len = 6;
    //IP 协议地址长度
    arp_head->pro_len = 4;
    //操作类型：占2字节，指定本次 ARP 报文类型。1标识 ARP 请求报文，2标识 ARP应答报文。
    arp_head->opcode = swap16(ARP_REQUEST);
    // ARP 操作类型为 ARP_REQUEST
    // 调用 ethernet_out 函数将 ARP 报文发送出去
    //printf("send a APR request\n");
    //ethernet_out(&txbuf, default_mac, NET_PROTOCOL_ARP);
    ethernet_out(&txbuf, bc_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，查看报文是否完整，
 *        检查项包括：硬件类型，协议类型，硬件地址长度，协议地址长度，操作类型
 *        
 *        接着，调用arp_update更新ARP表项
 *        查看arp_buf是否有效，如果有效，则说明ARP分组队列里面有待发送的数据包。
 *        即上一次调用arp_out()发送来自IP层的数据包时，由于没有找到对应的MAC地址进而先发送的ARP request报文
 *        此时，收到了该request的应答报文。然后，根据IP地址来查找ARM表项，如果能找到该IP地址对应的MAC地址，
 *        则将缓存的数据包arp_buf再发送到ethernet层。
 * 
 *        如果arp_buf无效，还需要判断接收到的报文是否为request请求报文，并且，该请求报文的目的IP正好是本机的IP地址，
 *        则认为是请求本机MAC地址的ARP请求报文，则回应一个响应报文（应答报文）。
 *        响应报文：需要调用buf_init初始化一个buf，填写ARP报头，目的IP和目的MAC需要填写为收到的ARP报的源IP和源MAC。
 * 
 * @param buf 要处理的数据包
 */
void arp_in(buf_t *buf)
{
    
    // TODO
    //首先做报头检查，查看报文是否完整。
    arp_pkt_t *arp = (arp_pkt_t *)buf->data;
    int opcode = swap16(arp->opcode);
    
    if (arp->hw_type != swap16(ARP_HW_ETHER) ||
        arp->pro_type != swap16(NET_PROTOCOL_IP) ||
        arp->hw_len != NET_MAC_LEN ||
        arp->pro_len != NET_IP_LEN ||
        (opcode != ARP_REQUEST && opcode != ARP_REPLY))
    {
        printf("incorrect arp head\n");
        return;
    }
    // 调用 arp_update 函数更新 ARP 表项。
    arp_update(arp->sender_ip,arp->sender_mac,ARP_VALID);
    if (arp_buf.valid == ARP_VALID)
    {
        arp_buf.valid = 0;
        uint8_t *mac_from_table = arp_lookup(arp_buf.ip); //根据 IP 地址来查找 ARP 表 (arp_table)
        //如果能找到该 IP
        //地址对应的 MAC 地址，则将缓存的数据包 arp_buf 再发送给以太网层，即调
        //用 ethernet_out 函数直接发出去。
        if (mac_from_table != NULL)
        {
            printf("\n3 mac: %x %x\n",mac_from_table[0],mac_from_table[1]); //test
            ethernet_out(&arp_buf.buf,mac_from_table,arp_buf.protocol);
        }
        
    }
    else
    //判断接收到的报文是否为 ARP_REQUEST 请求报文，并且该请求报文的 target_ip 是本机的 IP
    {
        if (opcode == ARP_REQUEST && arp->target_ip[0] == net_if_ip[0] &&
            arp->target_ip[1] == net_if_ip[1] &&
            arp->target_ip[2] == net_if_ip[2] &&
            arp->target_ip[3] == net_if_ip[3] ) //回应一个响应报文
        {
            
            buf_t req_buf;
            buf_init(&req_buf,28); //seg fault!
            arp_pkt_t *arp_head = (arp_pkt_t *)req_buf.data;
            
            memcpy(arp_head->sender_ip,my_ip,sizeof(my_ip));
            memcpy(arp_head->target_ip,arp->sender_ip,sizeof(my_ip));
            memcpy(arp_head->sender_mac,default_mac,sizeof(default_mac));
            memcpy(arp_head->target_mac,arp->sender_mac,sizeof(all_zero_mac));

            arp_head->hw_type = swap16(ARP_HW_ETHER);
            //上层协议类型
            arp_head->pro_type = swap16(NET_PROTOCOL_IP);
            //MAC 地址长度
            arp_head->hw_len = 6;
            //IP 协议地址长度
            arp_head->pro_len = 4;
            //操作类型：占2字节，指定本次 ARP 报文类型。1标识 ARP 请求报文，2标识 ARP应答报文。
            arp_head->opcode = swap16(ARP_REPLY);

            //printf("\n1 mac: %x %x\n",arp->sender_mac[0],arp->sender_mac[1]); //test
            ethernet_out(&req_buf,arp->sender_mac,NET_PROTOCOL_ARP);
            
        }
        
    }
}

/**
 * @brief 处理一个要发送的数据包
 *        你需要根据IP地址来查找ARP表
 *        如果能找到该IP地址对应的MAC地址，则将数据报直接发送给ethernet层
 *        如果没有找到对应的MAC地址，则需要先发一个ARP request报文。
 *        注意，需要将来自IP层的数据包缓存到arp_buf中，等待arp_in()能收到ARP request报文的应答报文
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TODO
    uint8_t *mac_from_table = arp_lookup(ip); //根据 IP 地址来查找 ARP 表 (arp_table)
    
    // 如果能找到该 IP 地址对应的 MAC 地址，则将数据包直接发送给以太网层，即
    //调用 ethernet_out 函数直接发出去。
    if (mac_from_table != NULL)
    {
        printf("\n2 mac: %x %x\n",mac_from_table[0],mac_from_table[1]); //test
        ethernet_out(buf, mac_from_table, protocol);
    }
    //如果没有找到对应的 MAC 地址，则调用 arp_req 函数，发一个 ARP request
    //报文。
    else
    {
        
        //arp_buf.buf = *buf; //将来自 IP 层的数据包缓存到 arp_buf 的 buf 中
        memcpy(&arp_buf.buf,buf,sizeof(buf_t));
        arp_buf.valid = 1;
        memcpy(arp_buf.ip,ip,sizeof(ip));
        memcpy(&arp_buf.protocol,&protocol,sizeof(protocol));
        //printf("\nrequest: %d %d\n",ip[0],ip[3]);
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        arp_table[i].state = ARP_INVALID;
    arp_buf.valid = 0;
    arp_req(net_if_ip);
}