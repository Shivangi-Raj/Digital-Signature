import pymongo
import dns
import certifi

# client = pymongo.MongoClient("mongodb+srv://shivangi_raj:shivangi_raj@cluster0.3vdqz.mongodb.net/DigitalSignature?retryWrites=true&w=majority")
client =pymongo.MongoClient("mongodb+srv://shivangi_raj:shivangi_raj@cluster0.3vdqz.mongodb.net", tlsCAFile=certifi.where())
db = client['DigitalSignature']
records=db['keys']
print(client.list_database_names())
# print(db,records)
sample_doc={"name":"Honey@gmail.com","password":"hello","publicKey1":"12345","publicKey2":"6789"}
name="Honeyy@gmail.com"
key=records.find_one({"name":name})
print(key)
# records.insert_one(sample_doc)

print("success")

