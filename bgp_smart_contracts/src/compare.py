#!/usr/bin/python3

import subprocess
import csv
import sys
import itertools
import pymongo
from operator import countOf

client = pymongo.MongoClient('10.3.0.3', 27017)
collection=client["bgp_db"]["known_bgp"]

#python3 converter.py test.mrt dump.csv single.csv compare.csv

#infile=sys.argv[1] 
#dump=sys.argv[2]
#infile2=sys.argv[3]
#outfile=sys.argv[4]
#local_asn=sys.argv[5]

def compiler(infile,dump,infile2,outfile,local_asn):
  subprocess.run(["bgpdump", "-M", str(infile), "-O", str(dump)])

  with open(str(dump) ,'r', newline='' ) as singlecsv:
    output=[]
    blank_csv = csv.reader(singlecsv, delimiter='|')
    for row in blank_csv:
      x=row[5].split('/')
      output.append([x[0],x[1],row[6]])
    #print(output)


  with open(str(infile2), 'r', newline='') as outputcsv:
    inputcsv=[]
    checker=csv.reader(outputcsv, delimiter='\t')
    for row in checker:
       inputcsv.append([row[1], row[3], row[4], row[5]])
    print("=====================")
    #print(inputcsv)

  with open(str(outfile), 'w', newline='') as outputcsv:
    #write_out=csv.writer(outputcsv, delimiter='|')
    for i,j in itertools.product(inputcsv, output):
      #print(i[0])
      #print(j[0])
      print('================')
      
      if i[0]==j[0]:
        seg1=j[2].split(' ')
        seg2=list(map(int, seg1))
        print ("seg2 is: ",seg2)
        print(i[0],j[0])
        path2,path3, path4=path_validate(seg2,local_asn)
        write_out=csv.writer(outputcsv, delimiter='\t')
        write_out.writerow([i[0],i[1],i[2],i[3],j[0],path2,path3,path4])
      else:
         pass  
        
        
def path_validate(segment_path, local_asn):


    segment_path.insert(0,local_asn)
    validation={}
    for indx, asn in enumerate(segment_path):
       if indx == len(segment_path)-1:
          if all(value == True for value in validation.values()):
              print("Path is fully verified",validation)
              percent=100
              return validation, percent, indx 
          else:
              print("The percentage of path validated is: ", countOf(validation.values(), True)/len(validation))
              percent=countOf(validation.values(), True)/len(validation)
              return validation, percent, indx
              
       elif collection.count_documents({'labels.asn': str(asn), 'labels.neighbors': {'$in': [segment_path[indx+1]]}}) == 1:
          validation[asn] = True
           
       else:
          validation[asn] = False   

if __name__=='__main__':
   compiler(sys.argv[1],sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
