from scapy.all import *
import code 
#import urllib3
import csv
import numpy as np
import matplotlib.pyplot as plt
 


packets = rdpcap("residencia.pcapng")

###### Types #####

type_Management = 0
type_Control = 1
type_Data = 2
type_Extension = 3

###################

###### Types-Count #####

qnt_type_Management = 0
qnt_type_Control = 0
qnt_type_Data = 0
qnt_type_Extension = 0

###################

###### Subtypes-Management #######
subtype_Management_Association_Request = 0
subtype_Management_Association_Response = 1
subtype_Management_Reassociation_Request = 2
subtype_Management_Reassociation_Response = 3
subtype_Management_Probe_Request = 4
subtype_Management_Probe_Response = 5
subtype_Management_Timing_Advertisement = 6
subtype_Management_Reserved_7 = 7
subtype_Management_Beacon = 8
subtype_Management_ATIM = 9
subtype_Management_Disassociation = 10
subtype_Management_Authentication = 11
subtype_Management_Deauthentication = 12
subtype_Management_Action  = 13
subtype_Management_NACK = 14
subtype_Management_Reserved_15 = 15

#######################

###### Subtypes-Management-Count #######
qnt_subtype_Management_Association_Request = 0
qnt_subtype_Management_Association_Response = 0
qnt_subtype_Management_Reassociation_Request = 0
qnt_subtype_Management_Reassociation_Response = 0
qnt_subtype_Management_Probe_Request = 0
qnt_subtype_Management_Probe_Response = 0
qnt_subtype_Management_Timing_Advertisement = 0
qnt_subtype_Management_Reserved_7 = 0
qnt_subtype_Management_Beacon = 0
qnt_subtype_Management_ATIM = 0
qnt_subtype_Management_Disassociation = 0
qnt_subtype_Management_Authentication = 0
qnt_subtype_Management_Deauthentication = 0
qnt_subtype_Management_Action  = 0
qnt_subtype_Management_NACK = 0
qnt_subtype_Management_Reserved_15 = 0

#######################


###### Subtypes-Control #######
subtype_Control_Reserved_0 = 0
subtype_Control_Reserved_1 = 1
subtype_Control_Trigger = 2
subtype_Control_Reassociation_Response = 3
subtype_Control_Beamforming_Report_Poll  = 4
subtype_Control_VHT_HE_NDP_Announcement = 5
subtype_Control_Control_Frame_Extension = 6
subtype_Control_Control_Wrapper = 7
subtype_Control_BAR = 8 	#Block Ack Request
subtype_Control_BA = 9		# Block Ack
subtype_Control_PS_Poll = 10
subtype_Control_RTS = 11
subtype_Control_CTS = 12
subtype_Control_ACK  = 13
subtype_Control_CF_End = 14
subtype_Control_CF_End_CF_ACK = 15

#######################

###### Subtypes-Control-Count #######
qnt_subtype_Control_Reserved_0 = 0
qnt_subtype_Control_Reserved_1 = 0
qnt_subtype_Control_Trigger = 0
qnt_subtype_Control_Reassociation_Response = 0
qnt_subtype_Control_Beamforming_Report_Poll  = 0
qnt_subtype_Control_VHT_HE_NDP_Announcement = 0
qnt_subtype_Control_Control_Frame_Extension = 0
qnt_subtype_Control_Control_Wrapper = 0
qnt_subtype_Control_BAR = 0 	#Block Ack Request
qnt_subtype_Control_BA = 0		# Block Ack
qnt_subtype_Control_PS_Poll = 0
qnt_subtype_Control_RTS = 0
qnt_subtype_Control_CTS = 0
qnt_subtype_Control_ACK  = 0
qnt_subtype_Control_CF_End = 0
qnt_subtype_Control_CF_End_CF_ACK = 0

#######################


###### Subtypes-Data #######
subtype_Data_Data = 0
subtype_Data_Data_CF_ACK = 1
subtype_Data_Data_CF_Poll = 2
subtype_Data_Data_CF_ACK_CF_Poll  = 3
subtype_Data_NULL = 4
subtype_Data_CF_ACK = 5
subtype_Data_CF_Poll = 6
subtype_Data_CF_ACK_CF_Poll = 7
subtype_Data_QoS_Data = 8
subtype_Data_Qos_Data_CF_ACK = 9
subtype_Data_Qos_Data_CF_Poll = 10
subtype_Data_Qos_Data_CF_ACK_CF_Poll = 11
subtype_Data_QoS_NULL= 12
subtype_Data_Reserved  = 13
subtype_Data_QoS_CF_Poll = 14
subtype_Data_QoS_CF_ACK_CF_Poll = 15

#######################

###### Subtypes-Data-Count #######
qnt_subtype_Data_Data = 0
qnt_subtype_Data_Data_CF_ACK = 0
qnt_subtype_Data_Data_CF_Poll = 0
qnt_subtype_Data_Data_CF_ACK_CF_Poll  = 0
qnt_subtype_Data_NULL = 0
qnt_subtype_Data_CF_ACK = 0
qnt_subtype_Data_CF_Poll = 0
qnt_subtype_Data_CF_ACK_CF_Poll = 0
qnt_subtype_Data_QoS_Data = 0
qnt_subtype_Data_Qos_Data_CF_ACK = 0
qnt_subtype_Data_Qos_Data_CF_Poll = 0
qnt_subtype_Data_Qos_Data_CF_ACK_CF_Poll = 0
qnt_subtype_Data_QoS_NULL = 0
qnt_subtype_Data_Reserved  = 0
qnt_subtype_Data_QoS_CF_Poll = 0
qnt_subtype_Data_QoS_CF_ACK_CF_Poll = 0

#######################

## TO-DO Implementar a parte de acpturar a tabela diretamente do site da IEEE
'''def get_mac_table_file(filename="oui.txt"):
	http = urllib3.PoolManager()
	request = http.request('GET', "http://standards.ieee.org/develop/regauth/oui/oui.txt")
	with open(filename, "w") as f:
		for line in request.data:
			f.write(line)


def parse_mac_table_file(filename="oui.txt"):
	ven_arr = []
	with open(filename, "r") as f:
		for line in f:
			if "(base 16)" not in line:
				continue
			ven = tuple(re.sub("\s*([0-9a-zA-Z]+)[\s\t]*\(base 16\)[\s\t]*(.*)\n", r"\1;;\2", line).split(";;"))
			ven_arr.append(ven)
	return ven_arr
'''
ap_list = []
ap_with_rts_cts = []
clients_list = []
vendors = []

with open('oui.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    aux = list(reader)

for line in aux:
    vendorTuple = (line[1],line[2])
    vendors.append(vendorTuple)


def get_vendor_prefix(mac):
    aux = mac.split(":")
    return  aux[0] + aux[1] + aux[2]


#ap_list_complete = []

def get_vendor_origin(ap):
    vendor_prefix = get_vendor_prefix(ap).upper()
    vendor = [item for item in vendors if item[0] == vendor_prefix]
    if vendor == []:
        if vendor_prefix in ["802AA8","822AA8","922AA8","A22AA8"]:
            return "UBIQUITI-VIRT"                          # conforme o seguinte link: https://help.ubnt.com/hc/en-us/articles/115002536648-UniFi-BSSID-to-MAC-Mapping
        else:#code.interact(local=dict(globals(), **locals()))
            return "UNKNOWN"          # https://superuser.com/questions/907827/private-mac-address :
    else:
        return vendor[0][1]

i = 0
for packet in packets:
    try:

        if packet.type == type_Management:

            qnt_type_Management += 1

            if packet.subtype == subtype_Management_Association_Request:
                qnt_subtype_Management_Association_Request += 1
                #code.interact(local=dict(globals(), **locals()))
                if (packet.addr2) not in (item[0] for item in clients_list) :
                    clients_list.append((packet.addr2,get_vendor_origin(packet.addr2),"A"))

            elif packet.subtype == subtype_Management_Association_Response:
                qnt_subtype_Management_Association_Response += 1

            elif packet.subtype == subtype_Management_Reassociation_Request:
                qnt_subtype_Management_Reassociation_Request += 1

            elif packet.subtype == subtype_Management_Reassociation_Response:
                qnt_subtype_Management_Reassociation_Response += 1

            elif packet.subtype == subtype_Management_Probe_Request:
                qnt_subtype_Management_Probe_Request += 1
                #code.interact(local=dict(globals(), **locals()))
                if (packet.addr2) not in (item[0] for item in clients_list) :
                    clients_list.append((packet.addr2,get_vendor_origin(packet.addr2),"P"))

            elif packet.subtype == subtype_Management_Probe_Response:
                qnt_subtype_Management_Probe_Response += 1

            elif packet.subtype == subtype_Management_Timing_Advertisement:
                qnt_subtype_Management_Timing_Advertisement += 1

            elif packet.subtype == subtype_Management_Reserved_7:
                qnt_subtype_Management_Reserved_7 += 1

            elif packet.subtype == subtype_Management_Beacon:
                qnt_subtype_Management_Beacon += 1
                if (packet.addr2) not in (item[0] for item in ap_list) :
                    ap_list.append((packet.addr2,packet.info,get_vendor_origin(packet.addr2)))
                #code.interact(local=dict(globals(), **locals()))

            elif packet.subtype == subtype_Management_ATIM:
                qnt_subtype_Management_ATIM += 1

            elif packet.subtype == subtype_Management_Disassociation:
                qnt_subtype_Management_Disassociation += 1

            elif packet.subtype == subtype_Management_Authentication:
                qnt_subtype_Management_Authentication += 1

            elif packet.subtype == subtype_Management_Deauthentication:
                qnt_subtype_Management_Deauthentication += 1

            elif packet.subtype == subtype_Management_Action:
                qnt_subtype_Management_Action += 1

            elif packet.subtype == subtype_Management_NACK:
                qnt_subtype_Management_NACK += 1

            else:
                qnt_subtype_Management_Reserved_15 +=1

        elif packet.type == type_Control:
            qnt_type_Control += 1
            if packet.subtype == subtype_Control_Reserved_0:
                qnt_subtype_Control_Reserved_0 += 1

            elif packet.subtype == subtype_Control_Reserved_1:
                qnt_subtype_Control_Reserved_1 += 1

            elif packet.subtype == subtype_Control_Trigger:
                qnt_subtype_Control_Trigger += 1

            elif packet.subtype == subtype_Control_Beamforming_Report_Poll:
                qnt_subtype_Control_Beamforming_Report_Poll += 1

            elif packet.subtype == subtype_Control_VHT_HE_NDP_Announcement:
                qnt_subtype_Control_VHT_HE_NDP_Announcement += 1

            elif packet.subtype == subtype_Control_Control_Frame_Extension:
                qnt_subtype_Control_Control_Frame_Extension += 1

            elif packet.subtype == subtype_Control_Control_Wrapper:
                qnt_subtype_Control_Control_Wrapper += 1

            elif packet.subtype == subtype_Control_BAR:
                qnt_subtype_Control_BAR += 1

            elif packet.subtype == subtype_Control_BA:
                qnt_subtype_Control_BA += 1

            elif packet.subtype == subtype_Control_PS_Poll:
                qnt_subtype_Control_PS_Poll += 1

            elif packet.subtype == subtype_Control_RTS:
                qnt_subtype_Control_RTS += 1
                if packet.addr2 not in ap_with_rts_cts :
                    ap_with_rts_cts.append(packet.addr2)
                #code.interact(local=dict(globals(), **locals()))

            elif packet.subtype == subtype_Control_CTS:
                qnt_subtype_Control_CTS += 1
                if packet.addr2 not in ap_with_rts_cts :
                    ap_with_rts_cts.append(packet.addr2)
                #code.interact(local=dict(globals(), **locals()))

            elif packet.subtype == subtype_Control_ACK:
                qnt_subtype_Control_ACK += 1

            elif packet.subtype == subtype_Control_CF_End:
                qnt_subtype_Control_CF_End += 1

            else:
                qnt_subtype_Control_CF_End_CF_ACK += 1


        elif packet.type == type_Data:
            qnt_type_Data += 1

            if packet.subtype == subtype_Data_Data:
                qnt_subtype_Data_Data += 1

            elif packet.subtype == subtype_Data_Data_CF_ACK:
                qnt_subtype_Data_Data_CF_ACK += 1

            elif packet.subtype == subtype_Data_Data_CF_Poll:
                qnt_subtype_Data_Data_CF_Poll += 1

            elif packet.subtype == subtype_Data_Data_CF_ACK_CF_Poll:
                qnt_subtype_Data_Data_CF_ACK_CF_Poll += 1

            elif packet.subtype == subtype_Data_NULL:
                qnt_subtype_Data_NULL += 1

            elif packet.subtype == subtype_Data_CF_ACK:
                qnt_subtype_Data_CF_ACK += 1

            elif packet.subtype == subtype_Data_CF_Poll:
                qnt_subtype_Data_CF_Poll += 1

            elif packet.subtype == subtype_Data_CF_ACK_CF_Poll:
                qnt_subtype_Data_CF_ACK_CF_Poll += 1

            elif packet.subtype == subtype_Data_QoS_Data:
                qnt_subtype_Data_QoS_Data += 1

            elif packet.subtype == subtype_Data_Qos_Data_CF_ACK:
                qnt_subtype_Data_Qos_Data_CF_ACK += 1

            elif packet.subtype == subtype_Data_QoS_CF_Poll:
                qnt_subtype_Data_Qos_Data_CF_Poll += 1

            elif packet.subtype == subtype_Data_QoS_CF_ACK_CF_Poll:
                qnt_subtype_Data_Qos_Data_CF_ACK_CF_Poll += 1

            elif packet.subtype == subtype_Data_QoS_NULL:
                qnt_subtype_Data_QoS_NULL += 1

            elif packet.subtype == subtype_Data_Reserved:
                qnt_subtype_Data_Reserved += 1
            elif packet.subtype == subtype_Data_QoS_CF_Poll:
                qnt_subtype_Data_QoS_CF_Poll += 1
            else:
                qnt_subtype_Data_QoS_CF_ACK_CF_Poll += 1
        else:
            qnt_type_Extension += 1
        #print(i)
        i +=1
    except:
        print("Pacote quebrado {0}".format(i))
        #i +=1

print('Type Management: {0}'.format(qnt_type_Management) +
	'\n\tAssosiation Request = {0}'.format(qnt_subtype_Management_Association_Request) +
	'\n\tAssosiation Response = {0}'.format(qnt_subtype_Management_Association_Response) + 
	'\n\tReassosiation Request = {0}'.format(qnt_subtype_Management_Reassociation_Request) +
	'\n\tReassosiation Response = {0}'.format(qnt_subtype_Management_Reassociation_Request) + 
	'\n\tProbe Request = {0}'.format(qnt_subtype_Management_Probe_Request) +
	'\n\tProbe Response = {0}'.format(qnt_subtype_Management_Probe_Response) + 
	'\n\tTiming Advertisement = {0}'.format(qnt_subtype_Management_Timing_Advertisement) +
	'\n\tReserved (0111) = {0}'.format(qnt_subtype_Management_Reserved_7) + 
	'\n\tBeacon = {0}'.format(qnt_subtype_Management_Beacon) +
	'\n\tATIM = {0}'.format(qnt_subtype_Management_ATIM) + 
	'\n\tDissassociation = {0}'.format(qnt_subtype_Management_Disassociation) +
	'\n\tAuthentication = {0}'.format(qnt_subtype_Management_Authentication) + 
	'\n\tDeauthentication = {0}'.format(qnt_subtype_Management_Deauthentication) +
	'\n\tAction = {0}'.format(qnt_subtype_Management_Action) + 
	'\n\tAction No Ack = {0}'.format(qnt_subtype_Management_NACK) +
	'\n\tReserved (1111) = {0}'.format(qnt_subtype_Management_Reserved_15) 
	)
print('Type Control: {0}'.format(qnt_type_Control) +
    '\n\tReserved (0000) = {0}'.format(qnt_subtype_Control_Reserved_0) +
    '\n\tReserved (0001) = {0}'.format(qnt_subtype_Control_Reserved_1) + 
    '\n\tTrigger = {0}'.format(qnt_subtype_Control_Trigger) +
    '\n\tBeanforming Report Poll = {0}'.format(qnt_subtype_Control_Beamforming_Report_Poll) + 
    '\n\tVHT/HE NDP Announcement  = {0}'.format(qnt_subtype_Control_VHT_HE_NDP_Announcement) +
    '\n\tControl Frame Extension = {0}'.format(qnt_subtype_Control_Control_Frame_Extension) + 
    '\n\tControl Wrapper  = {0}'.format(qnt_subtype_Control_Control_Wrapper) +
    '\n\tBlock Ack Request (BAR) = {0}'.format(qnt_subtype_Control_BAR) + 
    '\n\tBlock Ack (BA) = {0}'.format(qnt_subtype_Control_BA) +
    '\n\tPS-Poll = {0}'.format(qnt_subtype_Control_PS_Poll) + 
    '\n\tRTS = {0}'.format(qnt_subtype_Control_RTS) +
    '\n\tCTS = {0}'.format(qnt_subtype_Control_CTS) + 
    '\n\tACK = {0}'.format(qnt_subtype_Control_ACK) +
    '\n\tCF-End = {0}'.format(qnt_subtype_Control_CF_End) + 
    '\n\tCF-End + CF-ACK = {0}'.format(qnt_subtype_Control_CF_End_CF_ACK)  
    )

print('Type Data: {0}'.format(qnt_type_Data) +
    '\n\tData = {0}'.format(qnt_subtype_Data_Data) +
    '\n\tData + CF-ACK = {0}'.format(qnt_subtype_Data_Data_CF_ACK) + 
    '\n\tData + CF-Poll = {0}'.format(qnt_subtype_Data_Data_CF_Poll) +
    '\n\tData + CF-ACK + CF-Poll  = {0}'.format(qnt_subtype_Data_Data_CF_ACK_CF_Poll) + 
    '\n\tNull (no data)  = {0}'.format(qnt_subtype_Data_NULL) +
    '\n\tCF-ACK (no data) = {0}'.format(qnt_subtype_Data_CF_ACK) + 
    '\n\tCF-Poll (no data)  = {0}'.format(qnt_subtype_Data_CF_Poll) +
    '\n\tCF-ACK + CF-Poll (no data)  = {0}'.format(qnt_subtype_Data_CF_ACK_CF_Poll) + 
    '\n\tQoS Data = {0}'.format(qnt_subtype_Data_QoS_Data) +
    '\n\tQoS Data + CF-ACK = {0}'.format(qnt_subtype_Data_Qos_Data_CF_ACK) + 
    '\n\tQoS Data + CF-Poll = {0}'.format(qnt_subtype_Data_Qos_Data_CF_Poll) +
    '\n\tQoS Data + CF-ACK + CF-Poll  = {0}'.format(qnt_subtype_Data_Qos_Data_CF_ACK_CF_Poll) + 
    '\n\tQoS Null (no data) = {0}'.format(qnt_subtype_Data_QoS_NULL) +
    '\n\tReserved  = {0}'.format(qnt_subtype_Data_Reserved) + 
    '\n\tQoS CF-Poll (no data) = {0}'.format(qnt_subtype_Data_QoS_CF_Poll) +
    '\n\tQoS CF-ACK + CF-Poll (no data)  = {0}'.format(qnt_subtype_Data_QoS_CF_ACK_CF_Poll)   
    )


'''for ap in ap_list:
    vendor_prefix = get_vendor_prefix(ap[0]).upper()
    vendor = [item for item in vendors if item[0] == vendor_prefix]
    if vendor == []:
        ap_list_complete.append((ap[0],ap[1],"UNKNOWN"))
    else:
        ap_list_complete.append((ap[0],ap[1],vendor[0][1]))
'''
'''for a in ap_list:
    print(a)
    #print(ap[0],ap[1],vendor)
'''
#print("########################################################################")
f1= open("UNKNOWN_clients_Residencial.txt","w+")
for client in clients_list:
    if client[1] == 'UNKNOWN':
        f1.write("{0}\n".format(client[0]))
f1.close()
    
print("########################################################################")
f2= open("UNKNOWN_APs_Residencial.txt","w+")
for ap in ap_list:
    #print(ap)
    if ap[2] == 'UNKNOWN':
        f2.write("{0}\n".format(ap[0]))
f2.close()
#[item for item in a if item[0] == 1]



ap_with_rts_cts_sorted = [x[0] for x in ap_list if x[0] in ap_with_rts_cts] # pegando apenas os APs e não os clientes que usam RTS/CTS

# PReparando os dados para serem plotados.
client_manufacuter_list = []                          # lista de fabricantes de dispositivos clientes/quantidade de dispositivos fabricados 

client_manufactures_all = list(item[1] for item in clients_list)             # lista com total de nomes de fabricantes
client_manufactures_uniq = list(set(item[1] for item in clients_list)) # lista unica de nomes de fabricantes

for client in client_manufactures_uniq:
    if client not in (item[0] for item in client_manufacuter_list):
        client_manufacuter_list.append((client,client_manufactures_all.count(client)))
#print(client_manufacuter_list)

ap_manufacuter_list = []                          # lista de fabricantes de dispositivos aps/quantidade de dispositivos fabricados 

ap_manufactures_all = list(item[2] for item in ap_list)             # lista com total de nomes de fabricantes
ap_manufactures_uniq = list(set(item[2] for item in ap_list))       # lista unica de nomes de fabricantes

for ap in ap_manufactures_uniq:
    if ap not in (item[0] for item in ap_manufacuter_list):
        ap_manufacuter_list.append((ap,ap_manufactures_all.count(ap)))
#print(ap_manufacuter_list)


#### Plot Client status
client_manufacuter_list.sort(key = lambda x: x[1])
height_client = list(item[1] for item in client_manufacuter_list)
bars_client = tuple(list(item[0] for item in client_manufacuter_list))

y_pos_client = np.arange(len(bars_client))
 
# Create bars_client
bar_plot = plt.bar(y_pos_client, height_client,tick_label=[str(x) for x in height_client])
 
# Create names on the x-axis

plt.title("Clientes -> TOTAL: {0}".format(len(clients_list)), fontweight='bold', color = 'black', fontsize='18')
plt.xticks(y_pos_client, bars_client,rotation=90)
plt.subplots_adjust(bottom=0.5, top=0.90)
plt.ylabel('Quantidade', fontweight='bold', color = 'black', fontsize='14')
plt.xlabel('Fabricante', fontweight='bold', color = 'black', fontsize='14')

def autolabel_client(rects):
    for idx,rect in enumerate(bar_plot):
        height = rect.get_height()
        plt.text(rect.get_x() + rect.get_width()/2., 1.05*height,
                height_client[idx],
                ha='center', va='bottom', rotation=0)

autolabel_client(bar_plot)
 

# Show graphic
plt.show()



#### Plot AP status
ap_manufacuter_list.sort(key = lambda x:x[1])
height_ap = list(item[1] for item in ap_manufacuter_list)
bars_ap = tuple(list(item[0] for item in ap_manufacuter_list))

y_pos_ap = np.arange(len(bars_ap))
 
# Create bars_ap
bar_plot = plt.bar(y_pos_ap, height_ap)


 
# Create names on the x-axis

plt.title("APs -> TOTAL: {0}".format(len(ap_list)), fontweight='bold', color = 'black', fontsize='18')
plt.xticks(y_pos_ap, bars_ap,rotation=90)
plt.subplots_adjust(bottom=0.5, top=0.90)
plt.ylabel('Quantidade', fontweight='bold', color = 'black', fontsize='14')
plt.xlabel('Fabricante', fontweight='bold', color = 'black', fontsize='14')

def autolabel_ap(rects):
    for idx,rect in enumerate(bar_plot):
        height = rect.get_height()
        plt.text(rect.get_x() + rect.get_width()/2., 1.05*height,
                height_ap[idx],
                ha='center', va='bottom', rotation=0)

autolabel_ap(bar_plot)
 
# Show graphic
plt.show()



#### Plotando APs que utilizam/não utilizam RTS/CTS

labels = 'Utiliza', 'Não Utiliza'
sizes = [len(ap_with_rts_cts_sorted), len(ap_list) - len(ap_with_rts_cts_sorted)]
#explode = (0, 0.1, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

fig1 = plt.plot()
plt.title("Utilização de RTS/CTS", fontweight='bold', color = 'black', fontsize='18')
plt.xlabel('Total APs: {0}'.format(len(ap_list)), fontweight='bold', color = 'black', fontsize='14')
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        shadow=True, startangle=90)
plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

plt.show()


#### Plotando Distribuição de pacotes por tipo

labels = 'Management','Control', 'Data', 'Extension'
sizes = [qnt_type_Management, qnt_type_Control, qnt_type_Data, qnt_type_Extension]
#explode = (0, 0.1, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

fig1 = plt.plot()
plt.title("Distribuição de pacotes", fontweight='bold', color = 'black', fontsize='18')
plt.xlabel('Total Pacotes: {0}'.format(qnt_type_Management + qnt_type_Control + qnt_type_Data + qnt_type_Extension), fontweight='bold', color = 'black', fontsize='14')
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        shadow=True, startangle=90)
plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

plt.show()