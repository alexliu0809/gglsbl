import gzip
import json
from safebrowsing_database import *

def parse_dump_and_store(dump_filename, db_conn):

	# extract record_date
	record_date = dump_filename.split(".")[0].split("_")[1]

	with gzip.GzipFile(dump_filename, 'r') as fin:
		print("Reading Raw Bytes")
		json_bytes = fin.read()

	print("Decoding Bytes")
	json_string = json_bytes.decode()

	print("Loads JSON")
	data = json.loads(json_string)

	for idx, response in enumerate(data["responses"]):
		print("Response Number: {}".format(idx))
		#if idx == 0:
			#print(response)
		
		if "matches" in response:
			# save hash of last record
			previous_hash = None
			for item in response['matches']:
				# hash, primary info
				threat_hash = item['threat']['hash']
				if threat_hash != previous_hash:
					previous_hash = threat_hash
					insert_into_threat_entry(db_conn, threat_hash)
				
				# other info
				threat_type = item['threatType']
				threat_entry_type = item['threatEntryType']
				threat_platform = item['platformType']

				records = [threat_hash, threat_type, threat_entry_type, threat_platform, record_date]
				records = ['"{}"'.format(i) for i in records]

				insert_into_threat_records(db_conn, records)
				#print("{}:{}".format(item['threatType'],item['threat']['hash']))
		
		else:
			# There are two types of errors: Empty or 503,
			# 503 is caused by having too many items.
			# See this: https://github.com/google/safebrowsing/issues/93
			#print("Error Response:")
			#print(response)
			continue

