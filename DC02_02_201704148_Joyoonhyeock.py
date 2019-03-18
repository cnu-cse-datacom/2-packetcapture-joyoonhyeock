import socket
import struct

def parsing_ethernet_header(data): 
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("======ehternet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_adress:", ether_dest)
    print("ip_version",ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header = struct.unpack("!2B3H2B1H4s4s", data)
    ip_version_IHL = ip_header[0]
    ip_total_of_service = ip_header[1]
    ip_total_Length = ip_header[2]
    ip_Identification = ip_header[3]
    ip_Fragment_offset = ip_header[4]
    ip_Time_to_Live = ip_header[5]
    ip_Protocol = ip_header[6]
    ip_Header_checksum = ip_header[7]
    ip_Source_Address = ip_header[8]
    ip_Destination_Address = ip_header[9]

    #ip_Source_Address = ".".join(ip_Source_Address)
    #ip_Destiantion_Address = ".".join(ip_Source_Address)
    #flags = "0x"+((ip_Fragment_offset >> 13) & 7).hex()
    flags = (ip_Fragment_offset >> 13) & 7

    
    print("======ip_header======")
    print("ip_version:",(ip_version_IHL & 240) >> 4)
    print("ip_Length:",(ip_version_IHL & 15))
    print("differentiated_service_codepoint:",(ip_total_of_service & 252)>>2)
    print("explicit_congestion_notification:",(ip_total_of_service & 3))
    print("total_length:",ip_total_Length)
    print("flags:", hex(flags))
    print(">>>reserved_bit:",(flags & 4) >> 2)
    print(">>>not_fragments:",(flags & 2) >> 1)
    print(">>>fragments:",(flags & 1))
    print(">>>fragments_offset:", ip_Fragment_offset & 0x1FFF)
    print("Time to live:",ip_Time_to_Live)
    print("protocol:",ip_Protocol)
    print("header checksum:",hex(ip_Header_checksum))
    print("source_ip_address:",socket.inet_ntoa(ip_Source_Address))
    print("Destination_ip_address:",socket.inet_ntoa(ip_Destination_Address))
    
    if ip_Protocol == 6:
        return 6
    elif ip_Protocol == 17:
        return 17





def parsing_tcp_header(data):
    tcp_header = struct.unpack("!2H2I2B3H",data)
    tcp_Source_port = tcp_header[0]
    tcp_Destination_port = tcp_header[1]
    tcp_Sequence_number = tcp_header[2]
    tcp_Acknowledgement_number = tcp_header[3]
    tcp_Offset_Reserved = tcp_header[4]
    tcp_Tcpflag = tcp_header[5]
    tcp_Window = tcp_header[6]
    tcp_Checksum = tcp_header[7]
    tcp_Urgent_pointer = tcp_header[8]



    print("@@@@@@@@@@@@@@@@@@@@@@@tcp_header@@@@@@@@@@@@@@@@@@@@@@@")
    print("src_port:",tcp_Source_port)
    print("des_port:",tcp_Destination_port)
    print("seq_num:",tcp_Sequence_number)
    print("ack_num:",tcp_Acknowledgement_number)
    print("header_len:",(tcp_Offset_Reserved & 240) >> 4)
    print("flags:",tcp_Tcpflag)
    print(">>>reserved:",tcp_Offset_Reserved & 15)
    print(">>>nonce:",((tcp_Tcpflag) & 128) >>7)
    print(">>>cwr:",(tcp_Tcpflag) & 64 >> 6)
    print(">>>urgent:",(tcp_Tcpflag) & 32 >> 5)
    print(">>>ack:",(tcp_Tcpflag) & 16 >> 4)
    print(">>>push:",(tcp_Tcpflag) & 8 >> 3)
    print(">>>reset:",(tcp_Tcpflag) & 4 >>2)
    print(">>>syn:",(tcp_Tcpflag) & 2 >> 1)
    print(">>>fin:",(tcp_Tcpflag) & 1)
    print("window_size_value:",tcp_Window)
    print("Checksum:",tcp_Checksum)
    print("urgent_pointer:",tcp_Urgent_pointer)





def parsing_udp_header(data):
    udp_header = struct.unpack("!4H",data)
    udp_Source_port = udp_header[0]
    udp_Destination_port = udp_header[1]
    udp_Length = udp_header[2]
    udp_Checksum = udp_header[3]


    print("#######################udp_header########################")
    print("src_port:",udp_Source_port)
    print("dst_port:",udp_Destination_port)
    print("leng:",udp_Length)
    print("header checksum:",hex(udp_Checksum))

recv_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(0x800))

while True:
    data = recv_socket.recvfrom(2000)
    parsing_ethernet_header(data[0][0:14])
    protocol = parsing_ip_header(data[0][14:34])
    if protocol == 6:
        parsing_tcp_header(data[0][34:54])
    elif protocol == 17:
        parsing_udp_header(data[0][34:42])










