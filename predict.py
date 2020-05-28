#-*-coding:utf-8-*-
import pickle
import tensorflow as tf
import numpy as np
from keras.models import load_model
from collections import Counter
import os
import sys
import struct

model = load_model('./16_LSTM_CNN_pkt2flow_631_py36.h5',custom_objects={'tf': tf})
PACKET_LEN=784
label_list = {'B/WeiBo': 1, 'B/Web': 2, 'B/FTP': 3,
              'B/JianShu': 4, 'B/MySQL': 5, 'B/WorldOfWarcraft': 6,
              'M/Nmap': 7, 'M/Shifu': 8, 'M/Geodo': 9, 'M/Botnet': 10, 'M/SshAttack': 11,
              'M/Htbot': 12, 'M/Tinb': 13, 'M/Virut': 14, 'M/Cridex': 15, 'M/Dewdro': 16}

def readpcap_getdata(pcap_path):
    fpcap = open(pcap_path, 'rb')
    string_data = fpcap.read()
    #print(pcap_path)
    # pcap文件的数据包解析
    packet_num = 0
    packet_data = []
    pcap_packet_header = {}
    i = 24
    list_data = []

    while (i < len(string_data)):
        # 数据包头各个字段
        pcap_packet_header['GMTtime'] = string_data[i:i + 4]
        pcap_packet_header['MicroTime'] = string_data[i + 4:i + 8]
        pcap_packet_header['caplen'] = string_data[i + 8:i + 12]
        pcap_packet_header['len'] = string_data[i + 12:i + 16]
        # 求出此包的包长len
        try:
            packet_len = struct.unpack('I', pcap_packet_header['len'])[0]
        except:
            print(pcap_path)
        # 写入此包数据
        #会有空包
        data_info = string_data[i + 16:i + 16 + packet_len]
        if len(data_info)==0:
            print(pcap_path,' have empty packet')
        if len(data_info)>0:
            packet_data.append(data_info)
            packet_num += 1
        i = i + packet_len + 16


    # pacp文件里的数据包信息
    for i in range(packet_num):
        data = {}
        data['info'] = packet_data[i]
        list_data.append(data)
    fpcap.close()
    # print(list_data)
    # sys.exit(0)

    return list_data

def dataprocess(data):
    Xbatch = np.ones((len(data),PACKET_LEN),dtype=np.int64) * -1
    for i, packet in enumerate(data):
        info = packet['info']
        for j, byte in enumerate(info[:PACKET_LEN if len(info) > PACKET_LEN else len(info)]):
            Xbatch[i, (PACKET_LEN - 1 - j)] = byte
    return Xbatch

def predict(pcap_path):
    pred_data = readpcap_getdata(pcap_path)
    data_generator = dataprocess(pred_data)
    predict = model.predict(data_generator)
    predict = np.argmax(predict, axis=1)
    # 统计一下，这里就直接屏幕输出结果了，有其他输出需要再改吧。
    count_list = {}
    count = Counter(predict)
    # print(count)
    for k, v in label_list.items():
        if v in count.keys():
            count_list[k] = count[v]
    print(count_list)



if __name__=='__main__':

    count = 0
    while True:
        filename = "./Pcap/demo" + str(count) + ".pcap"  # Split the capture pcap everytime
        path = "./PcapSplit/demo" + str(count) + "/"  #存放切分后流量的位置

        if not os.path.exists(path):
            os.makedirs(path)

        command = "tcpdump -i ens33 -n -B 919400 -c 100 -w " + filename
        os.system(command)
        print("Capture over")

        splitCommand = './pkt2flow/pkt2plow -uvx -o ' + path
        os.system(splitCommand)

        """
        生成后的目录结构应该是
        ./PcapSplit/demo0/udp
                          tcp_syn
                          等
        里面才是pcap文件                     
        """

        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                print(file_path)
                predict(file_path)
        count += 1


        """
        这个tcpdump抓出来的流量是那16个类流量混合pcap吗？-------如果是流量混合的pcap，这个pkt2flow切分有影响吗？
        如果抓出来的流量只是1个类的流量
        切分后不合并pcap预测会存在一个比较麻烦的问题
        就是这几个pcap的预测结果应该是一样的，会重复输出结果
        但是如果抓出来的流量只是一个类的。。。这好没意思呀
        """
        """
        目前看着相当于仅有分类，不能定位的感觉
        """






