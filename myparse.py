from scapy.all import *
import code 
#import urllib3
import csv

packets = rdpcap("output2-02.cap")

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
        return "UNKNOWN"
    else:
        return vendor[0][1]

i = 0
for packet in packets:
    if packet.type == type_Management:

        qnt_type_Management += 1

        if packet.subtype == subtype_Management_Association_Request:
        	qnt_subtype_Management_Association_Request += 1

        elif packet.subtype == subtype_Management_Association_Response:
        	qnt_subtype_Management_Association_Response += 1

        elif packet.subtype == subtype_Management_Reassociation_Request:
        	qnt_subtype_Management_Reassociation_Request += 1

        elif packet.subtype == subtype_Management_Reassociation_Response:
        	qnt_subtype_Management_Reassociation_Response += 1

        elif packet.subtype == subtype_Management_Probe_Request:
        	qnt_subtype_Management_Probe_Request += 1

        elif packet.subtype == subtype_Management_Probe_Response:
        	qnt_subtype_Management_Probe_Response += 1

        elif packet.subtype == subtype_Management_Timing_Advertisement:
        	qnt_subtype_Management_Timing_Advertisement += 1

        elif packet.subtype == subtype_Management_Reserved_7:
        	qnt_subtype_Management_Reserved_7 += 1

        elif packet.subtype == subtype_Management_Beacon:
        	qnt_subtype_Management_Beacon += 1
        	if (packet.addr2,packet.info) not in ap_list :
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
    print(i)
    i +=1


print('Type Management: {0}'.format(type_Management) +
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
print('Type Control: {0}'.format(type_Control) +
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

print('Type Data: {0}'.format(type_Data) +
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
    print(a)'''
    #print(ap[0],ap[1],vendor)

for a in ap_with_rts_cts:
    print(a)
#[item for item in a if item[0] == 1]
'''
for vendor in vendors:
    print(vendor)
'''
#print(type_Management,type_Control,type_Data,type_Extension)
