#!/usr/bin/env python
from __future__   import print_function

import sys
import sqlite3
import tldextract
import re
import os, stat
import getopt

from configparser import ConfigParser
from datetime     import datetime
from datetime     import date
from os.path      import expanduser

# NOTE: CONFIG FILE CONTENT
config_object = ConfigParser()
config_object["DBINFO"] = {
    "database_path": "",
    "database_name": "",
    "table_name"   : ""
}

# NOTE: DEFAULT CONFIG PATH & FILENAME

default_path 		    = expanduser("~/.config")
default_folder	        = "n2db"
default_config_filename = "n2db.conf"

# NOTE: DATABASE HANDLE
global conn_handle

# NOTE: FILTER SPECIAL CHARACTERS (SQLi)
def scrub(table_name):
    return ''.join( chr for chr in table_name if chr.isalnum() )

# NOTE: TAKE DATA FROM NUCLEI AND PARSE IT
def extractData(data):

	nuclei_records = []
	lines_arr = data.splitlines()
	str_temp = ""

	# This to remove spaces between words 
	# But we keep spaces between brackets
	for j, line in enumerate(lines_arr):
		line_list = list(line)
		for i, elem in enumerate(line_list) :
			if line_list[i] == ' ': 
				if (line_list[i-1] != ']'):
					line_list[i] = '-'
		lines_arr[j] = str_temp.join(line_list)

	# When there is no more spaces between words
	# I remove the brackets and put each data into a variable
	for line in lines_arr:

		data_arr    = line.split(' ')
		vuln_name   = removeBrackets(data_arr[0])
		protocol    = removeBrackets(data_arr[1])
		severity    = removeBrackets(data_arr[2])
		url         = removeBrackets(data_arr[3])

		parsed_url  = tldextract.extract(url)
		domain_name = parsed_url.domain

		now         = datetime.now()
		current_time= now.strftime("%H:%M:%S")
		today       = date.today()
		today_date  = today.strftime("%d/%m/%Y")

		nuclei_records.append( (vuln_name, protocol, severity, url, domain_name, current_time, today_date) )

	return nuclei_records

# NOTE: FILTER BRACKETS FROM NUCLEI RESULT
def removeBrackets(data):
	char_to_remove = "[]"
	for c in char_to_remove:
		data = data.replace(c, '')
	return data

# NOTE: GET CONNECTION HANDLE
def connectToDB(db_file):
	global conn_handle
	conn = None
	try:
		conn_handle = sqlite3.connect(db_file)
	except Exception  as e:
		print ("[!] Can't connect to the database")
		return None

	print_if_not_fifo( "[*] Connected to the database")
	return conn_handle
				
# NOTE: FIRST CHECK IF TABLE EXISTS
def checkTable(conn_handle, table_name):
	
	table_name = scrub(table_name)

	if (conn_handle != None):
		    
		c = conn_handle.cursor()
		c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='{}' '''.format(table_name))
		
		if not c.fetchone()[0]:
			createTable(conn_handle, table_name)
			print_if_not_fifo("[*] First Time table creation [{}] ".format(table_name))
			conn_handle.commit()
		
		return True
	else:
		return False
				
def createTable(conn_handle, table_name):
	
	table_name = scrub(table_name)

	if (conn_handle != None and table_name):

		sql = '''
		create table if not exists {}(
									id	INTEGER NOT NULL,
										vuln_type	TEXT,
										protocol	TEXT,
										severity	TEXT,
										vuln_url	TEXT,
										domain	TEXT,
										time	TEXT,
										date	TEXT,
										PRIMARY KEY(`id`)
									);'''.format(table_name)

		cur = conn_handle.cursor()
		cur.execute(sql)
		conn_handle.commit()
		cur.close()
		
		return True
	else:
		return False

# NOTE: INSERT IN THE DATABASE, FILTER IS THERE'S ANY AND PRINT IN STDOUT
def executeInsert(conn_handle, table_name, data_arr):

	table_name = scrub(table_name)

	if (conn_handle != None):

		sql = "INSERT INTO {} (vuln_type, protocol, severity, vuln_url, domain, time, date)  VALUES (?,?,?,?,?,?,?)".format(table_name)

		cur = conn_handle.cursor()
		for line in data_arr:
			cur.execute(sql, line)

		conn_handle.commit()
		cur.close()
		
		# FILTER & FORWARD THE OUTPUT TO NOTIFY
		filterResponse(data_arr)
		
		return cur.lastrowid
	else:
		return None
		
# NOTE: GET FILE DATA AND PASS THEM TO INSERT FUNCTION
def toDB(file_content, table_data):
	
	global conn_handle
	
	database_path = file_content["database_path"]
	database_name = file_content["database_name"]
	table_name    = file_content["table_name"] 
	database_fullpath = database_path + '/' + database_name
	
	if (database_path != ""):
		if (database_path[-1] == '/'):
			database_path = database_path[:-1]

	if (database_name != "" and database_path != "" and  table_name != ""):
		rows = executeInsert(conn_handle, table_name, extractData(table_data))
		if (rows == None):
			print ("[!] Error occured, Quitting ...")
		else:
			print_if_not_fifo ("[*] Insert complete")
	else:
		print ("[!] Error in config file")

# NOTE: FILTER OUT THE XTERM & ANSI CHARACTERS
def filterXtermAnsi(data):
	return	re.sub(r'\x1b(\[.*?[@-~]|\].*?(\x07|\x1b\\))', '', data)

# NOTE: IF DATABASE CONFIG  FILE EXISTS
def isConfigFileExists(path):
	if os.path.isfile(path):
		return True
	else:
		return False

# NOTE: IF DIRECTORY EXISTS
def isDirectoryExists(path):

	if os.path.isdir(path):
		return True
	else:
		return False

# NOTE: DETECT IF THE CONFIG FILE EXISTS OR NOT AND CREATE
def initiateConfigFile():
	
	global conn_handle

	config_object_file = ConfigParser()

	if (isDirectoryExists(default_path + '/' + default_folder) == False):

		os.chdir(default_path)
		os.mkdir(default_folder)

		if (isConfigFileExists(default_path + '/' + default_folder + '/' +  default_config_filename) == False):
			with open(default_path + '/' +  default_folder + '/' + default_config_filename, 'w') as conf:
				config_object.write(conf)

			print ("[!] Config file must be configured => " + default_path + '/' + default_folder + '/' + default_config_filename)
			return None
	else:
		if (isConfigFileExists(default_path + '/' + default_folder + '/' +  default_config_filename) == False):
			with open(default_path + '/' +  default_folder + '/' + default_config_filename, 'w') as conf:
				config_object.write(conf)

			print ("[!] Config file must be configured => " + default_path + '/' + default_config_filename)
			return None
		else:
			config_object_file.read( default_path + '/' +  default_folder + '/' + default_config_filename)

	database_config = config_object_file["DBINFO"]
	
	# connect to the database
	database_path = database_config["database_path"]
	database_name = database_config["database_name"]
	table_name    = database_config["table_name"] 
	database_fullpath = database_path + '/' + database_name
	
	conn_handle = connectToDB(database_fullpath)
	
	return database_config
	
def getKeywords(keywords):
	
	keyword_list = []
	if (',' in keywords):
		keyword_list = keywords.split(',')
		return keyword_list
	
	keyword_list.append(keywords)
	return keyword_list
	
def cleanList(list_obj):
	
	if len(list_obj):
		list_obj = filter(None, list_obj)
		list_obj = filter(bool, list_obj)
		list_obj = filter(len, list_obj)
		list_obj = filter(lambda item: item, list_obj)
		
	return list_obj
	
# NOTE: FILTER RESPONSE BY USING KEYWORDS
# -fv waf-detect => won't notify you about this info through NOTIFY
# Now it can't filter, it forward all the result
# Most annoying ones: waf,cors,csp,hsts,x-frame,apache-version
def filterResponse(response):
	argv = sys.argv[1:]
	

	fl_vuln  =  ""
	fl_svr   =  ""
	fl_proto =  ""
	
	is_vuln  =  False
	is_svr   =  False
	is_proto =  False
	
	
	try:
		opts, args = getopt.getopt(argv, 'hv:p:s:', ['filter-vuln=','filter-proto=','filter-svr='])
		
		for out in response:
			for opt, arg in opts:
				
				if opt in ("-v","--filter-vuln"):
					#if (arg in out[0] and len(out[0]) >= 3):
					fl_vuln = arg #getKeywords(arg)
					is_vuln = True
						
				if opt in ("-p","--filter-proto"):
					#if (arg in out[1] and len(out[1]) >= 3):
					fl_proto = arg
					is_proto = True
						
				if opt in ("-s","--filter-svr"):
					#if (arg in out[2] and len(out[2]) >= 3):
					fl_svr = arg
					is_svr = True
						
				if (not is_vuln and not is_proto and not is_svr and opt != ""):
					raise
			
			#if (not fl_svr):
			#	fl_svr  = "\x1b"
			#if (not fl_proto):
			#	fl_proto = "\x1b"
			
			build_output_send(out, fl_vuln, fl_proto, fl_svr)
	except:
		print("[!] Doesn't recognize your parameter")
		help()
		sys.exit()
			
# NOTE: BUILD OUTPUT MSG
def build_output_send(msg, vuln, proto, svr):
	
	space = ""
	vuln_keywords     = getKeywords(vuln)
	severity_keywords = getKeywords(svr)
	protocol_keywords = getKeywords(proto)
	
	vuln_keywords     = cleanList(vuln_keywords)
	severity_keywords = cleanList(severity_keywords)
	protocol_keywords = cleanList(protocol_keywords)
	
	msg_vuln     = msg[0]
	msg_severity = msg[2]
	msg_protocol = msg[1]
		
	res_vuln     = bool([key for key in vuln_keywords if( key in msg_vuln)])
	res_severity = bool([key for key in severity_keywords if( key in msg_severity)])
	res_protocol = bool([key for key in protocol_keywords if( key in msg_protocol)])

	if (
		not res_vuln
		and 
		not res_severity
		and 
		not res_protocol
	   ):
		s = "[ Domain: {} ]|---------|[ Severity: {} ]|---------|[ Type: {} ]|---------|[ Protocol: {} ]|---------|[ URL: {} ]".format(msg[4], msg[2], msg[0], msg[1],msg[3])
		print(s)
	

# NOTE: PRINT SUCCESSFUL MESSAGES ONLY <> PIPED MODE
def print_if_not_fifo(msg):
	mode = os.fstat(0).st_mode
	if not stat.S_ISFIFO(mode) and not stat.S_ISREG(mode):
		print (msg)
 
# NOTE: PRINT TO STDOUT => FOR NOTIFY
def print_stdout(output_msg): 
    sys.stdout.write(output_msg)

# NOTE: QUIT IF TERMINAL MODE
def is_terminal_mode():
	mode = os.fstat(0).st_mode
	
	arg_file = ""
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'hv:p:s:', ['help=','filter-vuln=','filter-proto=','filter-svr='])
	except getopt.GetoptError:
		help()
		sys.exit()
			
	if not stat.S_ISFIFO(mode) and not stat.S_ISREG(mode):
		print("[!] Not yet. Piping mode or redirecting mode only")
		print(" => Ex piping:   cat nuclei_out.txt | ./n2d.py | notify")
		print(" => Ex redirect: ./n2d.py < nuclei_out.txt")
		print(" Use --help for more information")
		sys.exit()

# NOTE: HELP & USAGE ONLY IN TERMINAL MODE
def help():
	print("Usage: " + sys.argv[0] + " [Optional] --filter-vuln <vuln keyword> --filter-proto <protocol keyword> --filter-svr <severity keyword>")
	print('''Note : The program doesn't support native terminal mode.
	You must execute through piping or stdin redirect.\n''')
	print("=========================Example 1 ========================")
	print("Ex1  : cat nuclei_out.txt | " + sys.argv[0] + "  | notify")
	print("Ex2  : cat nuclei_out.txt | " + sys.argv[0] + " --filter-vuln \"cors,x-frame,waf\"  | notify")
	print("Ex3  : cat nuclei_out.txt | " + sys.argv[0] + " --filter-svr \"info, medium\"  | notify\n")
	print("=> By default the program will save all the data in DB.")
	print("=> If filters applied the record containing the keywords won't be printed, thus, not sent.\n")
	
	print("=========================Example 2 ========================")
	print("Ex3  : ./n2d.py < nuclei_out.txt")
	print("=>     If you want to put your nuclei result in the database") 
	print("===========================================================")
	print("Github => https://www.github.com/warber0x")
	print("===========================================================")
	
# NOTE: SOME COOL STUFF
def banner():
	print_if_not_fifo( '''
			
    )                               (           
 ( /(             (               ) )\ )    (   
 )\())   (        )\   (   (   ( /((()/(  ( )\  
((_)\   ))\   (  ((_) ))\  )\  )(_))/(_)) )((_) 
 _((_) /((_)  )\  _  /((_)((_)((_) (_))_ ((_)_  
| \| |(_))(  ((_)| |(_))   (_)|_  ) |   \ | _ ) 
| .` || || |/ _| | |/ -_)  | | / /  | |) || _ \ 
|_|\_| \_,_|\__| |_|\___|  |_|/___| |___/ |___/ 
By TheR3d0ne - Compatible with Slack 2020.V1
                                                
''')

# NOTE: MAIN BODY
def main():
	global conn_handle
	
	banner()
	
	is_terminal_mode()
	
	print_if_not_fifo("[*] Initiating ...")
	
	table_data = ""
	dbconfig = initiateConfigFile()
	if (dbconfig == None):
		print ("[!] Please check your config file")
		sys.exit()
	
	checkTable(conn_handle, dbconfig["table_name"])
		
	mode = os.fstat(0).st_mode
	if stat.S_ISFIFO(mode):
		table_data = filterXtermAnsi(sys.stdin.read())
		toDB(dbconfig, table_data)
		return
		
	elif stat.S_ISREG(mode):
		print_if_not_fifo("[*] Redirecting to STDIN, reading data ...")
		
		for line in sys.stdin:
			table_data = table_data + filterXtermAnsi(line)
			
		toDB(dbconfig, table_data)
		return
	'''
	else:
		if len(sys.argv) <= 1:
			print ('[!] Please provide nuclei output result')
				
			help()
			return
		
		arg_file = ""
		try:
			opts, args = getopt.getopt(sys.argv[1:], 'hf:', ['file=']) #FOR FUTURE USE => fv:fp:fs:', ['filter_vuln=','filter_proto=','filter_svr='])
		except getopt.GetoptError:
			help()
			sys.exit()
			
		for opt, arg in opts:
			if opt == '-h':
				help()
				sys.exit()
			elif opt in ("-f","--file"):
				arg_file = arg		
				
		print_if_not_fifo("[*] Executing in Terminal Mode ...")
		try:
			with open(arg_file, 'r') as conf:
				lines = conf.readlines()
			
			for line in lines:
				table_data = table_data + filterXtermAnsi(line)
			
			toDB(dbconfig, table_data)
		except: 
			print ("[!] Cannot read file data")
		
     	return
     '''

# NOTE: MAIN FUNCTION
main()
