from pymongo import MongoClient
# from random import randint
client = MongoClient('10.3.0.3', 27017)
# mydb = client["bgp_db"]

with open('testing123.txt', 'w') as dummy:
    dummy.write(str(client.list_database_names()))
