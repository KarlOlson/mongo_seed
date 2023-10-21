#!/usr/bin/python3
#To Run:
#Install scapy: $sudo pip install scapy
#Run Proxy Sniffer $sudo python3 <filename.py>
#Must run from sudo for packet processing privileges.
from operator import add
from netfilterqueue import NetfilterQueue
from scapy.all import *
# from Classes.Account import Account
from Utils.Utils import *
from Classes.PacketProcessing.MutablePacket import MutablePacket
from Classes.PacketProcessing.BGPUpdate import BGPUpdate
from Classes.PacketProcessing.Index import Index
from Classes.PacketProcessing.ConnectionTracker import ConnectionTracker
from Classes.PacketProcessing.FiveTuple import FiveTuple
from Classes.PacketProcessing.FlowDirection import FlowDirection
from Classes.PacketProcessing.DatabaseValidation import db_validate
from ipaddress import IPv4Address
from Classes.Account import Account
from operator import countOf
import os, sys
import datetime
import subprocess
import pymongo

local_asn=int(sys.argv[1])

ACCEPT_UNREGISTERED_ADVERTISEMENTS = True # set to False to remove all advertisements that are not registered

global_index = None
connections = None

#scapy does not automatically load items from Contrib. Must call function and module name to load.
load_contrib('bgp') 

#establish connection to mongo db for validation
client = pymongo.MongoClient('10.3.0.3', 27017)
#db = client["bgp_db"]
#collection = db["known_bgp"]
collection=client["bgp_db"]["known_bgp"]

################Establishes local IPTABLES Rule to begin processing packets############
QUEUE_NUM = 1
# insert the iptables FORWARD rule
os.system("iptables -I INPUT -p tcp --dport 179 -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
os.system("iptables -I INPUT -p tcp --sport 179 -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
os.system("iptables -I OUTPUT -p tcp --dport 179 -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
os.system("iptables -I OUTPUT -p tcp --sport 179 -j NFQUEUE --queue-num {}".format(QUEUE_NUM))


#set time and counter global variables for performance metrics/reporting
def get_datetime():
    return datetime.datetime.now()

old_print = print

#Performance Counters
db_time=0
db_packets=0
db_lookups=0

proxy_time1=0
proxy_packets1=0

proxy_time2=0
proxy_packets2=0

total_time=0
total_packets=0

path_time=0
path_lookups=0



#Packet processing function to query db info. Looks for BGPUpdate messages containing NLRI advertisements.
def pkt_in(packet):


    #Start counter metrics
    global  path_time, path_lookups, db_time, db_packets, proxy_time1, proxy_packets1, proxy_time2, proxy_packets2, db_lookups
        
    #Start counters for proxy handling time
    start_time1 = time.time_ns() // 1_000_000
    
    
    #Terminal Output Stats
    local_index = global_index.incr_index()
    def ts_print(*args, **kwargs):
        old_print(str(datetime.datetime.now()) + "--" + str(local_index), *args, **kwargs)
    print = ts_print
    print ("proxy start time:"+str(start_time1))
    
    
    
    


    #Get packet payload, convert to mutable packet so we can modify it if needed.
    #print("rx packet")
    pkt = IP(packet.get_payload())
    m_pkt = MutablePacket(pkt)
    #print(packet)
    print(m_pkt.show())


    #check if active BGP connection exists. If we modify packets, will need to handle TCP counters through this.
    if not connections.connection_exists(m_pkt):
        connections.add_connection(m_pkt)
    
    # checks for both bgp packet and bgp update
    if m_pkt.is_bgp_update(): 
        print("rx BGP Update pkt")
        try:
            # iterate over packet bgp payloads (bgp layers)
            layer_index = 0
            for payload in m_pkt.iterpayloads():
                if isinstance(payload,  scapy.contrib.bgp.BGPHeader):
                    most_recent_bgp_header = payload
                elif isinstance(payload, scapy.contrib.bgp.BGPUpdate):
                    layer_index += 1
                    print(type(payload))
                    # m_pkt.add_bgp_update(BGPUpdate())
                    update = BGPUpdate(most_recent_bgp_header, payload, layer_index)
                    if not update.has_withdraw_routes() and update.has_nlri_advertisements():
                        # Get the next hop ASN from the BGP packet
                        # next_hop_asn = update.get_next_hop_asn()
                        # next_hop_asn = m_pkt.get_next_hop_asn()
                        for count, nlri in enumerate(update.nlri()):
                            segment = update.get_segment(nlri)
                            print("nlri count: " + str(count))
                            print("BGP NLRI check: " + str(nlri.prefix))
                            print ("Advertised Segment: " + str(segment))
                            print ("validating advertisement for ASN: " + str(update.get_origin_asn()))
                            print ("ASN_Path is: ", update.asn_segment)
                            #Conduct call to DB to validate prefix/ASN ownership
                            validationResult, duration2 = db_validate(segment)
                            db_time+=duration2

                            validation_dict,duration3=path_validate(update.asn_segment, local_asn)
                            print("validation result is: ", validation_dict)
                            path_time+=duration3
                            #path_lookups+=paths

                            #if validationResult == validatePrefixResult.prefixValid:
                            #print("NLRI " + str(count) + " passed authorization...checking next ASN")
                            #elif validationResult == validatePrefixResult.prefixNotRegistered:
                                #print("Unregistered BGP")
                                #handle_unregistered_advertisement(m_pkt, nlri, validationResult, update)
                            #elif validationResult == validatePrefixResult.prefixOwnersDoNotMatch:
                                #handle_invalid_advertisement(m_pkt, nlri, validationResult, update)
                            #else:
                                #print("error. should never get here. received back unknown validationResult: " + str(validationResult))
                            
                            #Performance metric for verifying total packet
                        db_packets += 1
                        #print ("Whole NLRI Validation was: "+str(NLRI_time_sum)+" ms.")
                            
                        if m_pkt.is_bgp_modified():
                            print("BGP Update packet has been modified")
                        else:
                            print("BGP update and headers are not modified")
                            
                    else:
                        print("BGP Update packet has no NLRI advertisements")
                else:
                    print("Packet layer is not a BGPUpdate or BGPHeader layer")
            print ("All Advertised ASN's within all BGP Updates have been checked")
            if m_pkt.is_bgp_modified():
                print("BGP Update packet has been modified")
                connections.update_connection(m_pkt)
                print("setting modified bgp packet. accept:")
                m_pkt.recalculate_checksums()
                packet.set_payload(m_pkt.bytes())
            else:
                connections.update_connection(m_pkt)
                if m_pkt.are_headers_modified():
                    print("headers updated, accept header modified packet")
                    m_pkt.recalculate_checksums()
                    packet.set_payload(m_pkt.bytes())
                else:
                    print("packet not modified. accepting as is")
                    
            #Performance metrics for full proxy/db action
            duration1=(time.time_ns() // 1_000_000) - start_time1
            proxy_time1+=duration1
            proxy_packets1+=1
            print ("Full proxy/db  duration was: "+str(duration1)+" ms.")   
            print ("AVG db lookup duration was:" +str(db_time/db_lookups)+" ms. for "+str(db_lookups)+" lookups")
            print("Total db time was: "+str(db_time/db_packets))
            packet.accept()

        except IndexError as ie:
            print("index error. diff type of bgp announcement. accept packet. error: " + repr(ie))
            packet.accept()
            print("accepted other bgp type packet")
        except Exception as e: 
            print("bgp msg other: " + repr(e))
            packet.accept()
    else:
        print("not a bgp update packet. are headers modified? ")
        connections.update_connection(m_pkt)
        if m_pkt.are_headers_modified():
            m_pkt.recalculate_checksums()
            print("yes headers modified. set packet bytes.")
            packet.set_payload(m_pkt.bytes())
        print("accept non bgp packet")
        #Full proxy processing time (for non-lookup packets)
        duration3=(time.time_ns() // 1_000_000) - start_time1
        proxy_time2+=duration3
        proxy_packets2 += 1
        print ("proxy only duration was: "+str(duration3)+" ms.")
        packet.accept()
                   

        

def handle_unregistered_advertisement(m_pkt, nlri, validationResult, update):
    print ("AS " + str(update.get_origin_asn()) + " Failed Authorization. [" + str(validationResult) + "]. BGPUpdate layer: " + str(update.get_layer_index()))
    if ACCEPT_UNREGISTERED_ADVERTISEMENTS:
        print("Accepting unregistered advertisement")
    else:
        print("Dropping unregistered advertisement")
        remove_invalid_nlri_from_packet(m_pkt, nlri, update)

def handle_invalid_advertisement(m_pkt, nlri, validationResult, update):
    print ("AS " + str(update.get_origin_asn()) + " Failed Authorization. [" + str(validationResult) + "]. BGPUpdate layer: " + str(update.get_layer_index()))
    remove_invalid_nlri_from_packet(m_pkt, nlri, update)


def remove_invalid_nlri_from_packet(m_pkt, nlri, update):
    m_pkt.remove_nlri(nlri, update)
    if m_pkt.is_bgp_modified():
        print("bgp packet modified")
    else:
        print("ERROR: packet modification failed")


def path_validate(segment_path, local_asn):

    #set global counters for performanc metrics
    #global  path_validate_sum, path_lookup_counter
    #start_time = time.time_ns() // 1_000_000
    #print("Path start time:"+str(start_time))
    global  path_lookups
    start_time = time.time_ns() // 1_000_000

    segment_path.insert(0,local_asn)
    print ("Validating segment: ", segment_path)
    validation={}
    for indx, asn in enumerate(segment_path):
       if indx == len(segment_path)-1:
          if all(value == True for value in validation.values()):
              print("Path is fully verified",validation)
              duration=(time.time_ns() // 1_000_000) - start_time
              return validation, duration
          else:
              print("The percentage of path validated is: ", countOf(validation.values(), True)/len(validation))
              duration=(time.time_ns() // 1_000_000) - start_time
              return validation, duration
              
       elif collection.count_documents({'labels.asn': str(asn), 'labels.neighbors': {'$in': [segment_path[indx+1]]}}) == 1:
          validation[asn] = True
           
       else:
          validation[asn] = False 
       #db_lookup_sum+=duration
       path_lookups+=1  


def db_validate(segment):

    #set global counters for performanc metrics
    global  db_lookups
    db_lookups+=1
    start_time = time.time_ns() // 1_000_000
    print("Database start time:"+str(start_time))
    
    inIP = IPv4Address(segment[1])
    inSubnet = int(segment[2])
    inASN = int(segment[0])
    print ("Validating segment: AS" + str(inASN)+ " , " + str(inIP) + "/" + str(inSubnet))
    
    #DB lookup/validation
    ret=collection.find_one({'labels.net1_address': str(inIP) + "/" + str(inSubnet)},{'labels.asn':1})
    #ret = collection.find({'labels.net_0_address': str(inIP) + "/" + str(inSubnet
    print('retrieved db info') 
    #print(ret)
    validASN = ""
    validationResult=""
  
    try:
       validASN=ret['labels']['asn']
       #print(str(validASN)+'this is output of try')
       print(str(inASN)+' vs. '+ str(validASN))
    except:
       print('No Match Found - Except')
       validASN=""
        
    print('entering final comparison')
    
    if validASN == "":
        print ("Prefix not registered")
        validationResult=validatePrefixResult.prefixNotRegistered
    elif str(validASN) == str(inASN): 
        print ("Prefix is valid")
        validationResult=validatePrefixResult.prefixValid
    else:
        print ("Owners don't match")
        validationResult=validatePrefixResult.prefixOwnersDoNotMatch

    #final db performance metrics
    duration=(time.time_ns() // 1_000_000) - start_time
    #db_lookup_sum+=duration
    #db_lookups+=1
    
    print ("db Lookup Duration was: "+str(duration)+" ms.")
    return validationResult, duration


if __name__=='__main__':
    global_index = Index() 
    connections = ConnectionTracker()

    print("Accept Unregistered Advertisements Flag: " + str(ACCEPT_UNREGISTERED_ADVERTISEMENTS))

    # instantiate the netfilter queue
    nfqueue = NetfilterQueue()
 
    try:
        complete_time = time.time_ns() // 1_000_000
        nfqueue.bind(QUEUE_NUM, pkt_in)
        complete_duration=(time.time_ns() // 1_000_000) - complete_time 
        #nfqueue.bind(2, pkt_in)
        nfqueue.run()
    except KeyboardInterrupt:
        print('')
        # remove that rule we just inserted, going back to normal.
        os.system("iptables --flush")
        nfqueue.unbind()
        
        #print out final performance statistics over full run
        print ("Total Update packets:"+str(proxy_packets1))
        time_avg=proxy_time1/proxy_packets1 #removed proxy_packets1 and replace with db_packets
        print ("Proxy +DB average time for Update Packets:"+str(time_avg))
        print("non update packets: "+str(proxy_packets2))
        print ("Average Proxy Time (Non-Update Packets): "+str(proxy_time2/proxy_packets2))
        try:
            print ("Total DB packets:"+str(proxy_packets1))
            print("total db lookups: ", db_lookups)
            db_avg=db_time/proxy_packets1
            print("Average DB lookup time (whole NLRI):"+str(db_avg))
            print("Average NLRI lookup time: "+str(db_time/db_lookups))
            print("Average Proxy Overhead time: "+str((proxy_time1-db_time-path_time)/proxy_packets1))
            
        except:
            print("No db packets")
        try:
            print ("Total path validate  packets:"+str(proxy_packets1))
            path_avg=path_time/proxy_packets1
            print("Average path lookup time (whole path): "+str(path_avg))
            print("Average path lookup time (segments): ",path_time/path_lookups) 
        except:
            print("no path packets")
        #try:
            #full_lookup=db_time_sum/db_counter
            #print ("Full  DB packet time with lookup:"+str(full_lookup)+"ms")
        #except:
            #print("no DB packets")


