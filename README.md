# Nuclei to DB - N2DB

N2DB is a program that will help you to store you NUCLEI output in SQLite3 database. Also, this tool allows you to filter the output shown in the terminal while doing recon.
I developed this tool because I wanted to keep nuclei tool testing all vulnerabilities save them and send only the ones that are high or ciritical.

These are the features that N3DB have:
- Get Nuclei output text format and store it to a database
- Filter your output by using (--filter-vuln, --filter-svr, --filter-proto) to show only what you are interested into.
- The N2DB output is made to make the notification readable through "notify" tool. 

## Requirements:
- Download tldextract: `pip install tldextract`
- Sqlite3: `apt install sqlite3`

## Third party tools:
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Notify](https://github.com/projectdiscovery/notify)

## Configuration
- Download the N2DB: 
```
git clone https://github.com/warber0x/N2DB
```

- In the same folder where n2db.py resides, create a sqlite3 database and quit:
```
   root@linux:~/N2DB $ sqlite3
   Sqlite3>.save YOURDB
   Sqlite3>.quit
``` 
  => A database "YOURDB" should now be present in the same folder.

- Execute N2DB: 
```
python n2db.py
```
  =>  The first time execution will create a config file in `~/.config/n2db` named `n2db.conf`

- Go to the config folder and open the file using your prefered text editor:

```
[DBINFO]
database_path = FULL_PATH_TO_THE_DB               
table_name = CHOOSE_A_TABLE_NAME_TO_CREATE
database_name = YOURDB
```
- As shown above, put the name of the database you created in "**database_name**", fill the "**database_path**" with the location of your database freshly created. Finally, choose a name for your table.
- Save the file and try to execute the program by piping the  nuclei output sample to N2DB:

```
cat nuclei.txt | python n2db.py 
```

- The output should be visible in the terminal as well as the data is now stored in the database.

## Filters:
Sometimes we need to filter the output shown in our terminal without limiting our nuclei scanning. That's why I coded some useful filtering features to show just what you desire :)

### Available filters options:
- *--filter-vuln* : Filter records by vulnerability type. ex: `cat nuclei.txt | ./n2db.py --filter-vuln x-frame`
- *--filter-svr*  : Filter records by severity ex: info, low, medium, high
- *--filter-proto*: Filter records by protocol type ex: http, dns, smb ...

Let's imagine we do not want to show records contaning the keywords "x-frame" and "tech", all we have to do is:
```
cat nuclei.txt | ./n2db.py --filter-vuln "x-frame,tech"
```
The program will ignore to show the first 2 lines and print the third.

**Other examples**:
``` 
cat nuclei.txt | ./n2db.py --filter-proto dns
cat nuclei.txt | ./n2db.py --filter-svr "info, low" 
``` 

## Screenshots:


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.



