import mysql.connector

class sql_database:
    def __init__(self):
        self.mydb = mysql.connector.connect(
            #Using host=localhost as we are running database from our own machine
            host="localhost", 
            user="ENTER_DATABASE_USERNAME_HERE",
            password="ENTER_DATABASE_PASSWORD_HERE",
            database = "ENTER_DATABASE_NAME_HERE"
        )
        
    def display_database(self):
        #Function used to display database python is connected to
        mycursor = self.mydb.cursor(buffered=True)
        mycursor.execute("SHOW DATABASES")
        for x in mycursor:
            print(x)
            
    def display_database_tables(self):
        #Function used to display all tables in available databases
        mycursor = self.mydb.cursor(buffered=True)
        mycursor.execute("SHOW TABLES")
        for x in mycursor:
            print(x)
            
    def create_table(self, tablename):
        #Function used to create a new table based on given tablename string variable
        mycursor = self.mydb.cursor(buffered=True)
        mycursor.execute("CREATE TABLE %s (name VARCHAR(255), address VARCHAR(255))" % (tablename))
        
    def change_table_name(self, tablename, newname):
        #Function used to change the tablename from its original name to a new name
        mycursor = self.mydb.cursor(buffered=True)
        mycursor.execute("RENAME TABLE %s TO %s" % (tablename, newname))
        
    def add_primary_key(self, tablename):
        #Function adds Primary Key to table name specified in tablename variable
        mycursor = self.mydb.cursor(buffered=True)
        mycursor.execute("ALTER TABLE %s ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY" % (tablename))
        
    def add_column(self, tablename, columnname):
        #Function used to add column to a given table
        #tablename is the table to add column to and columnname is the name of the new column
        mycursor = self.mydb.cursor(buffered=True)
        mycursor.execute("ALTER TABLE %s ADD COLUMN %s VARCHAR(100)" % (tablename, columnname))
        
    def remove_column(self,tablename, columnname):
        #Function used to remove specified column from a specified tablename
        mycursor = self.mydb.cursor(buffered=True)
        mycursor.execute("ALTER TABLE %s DROP COLUMN %s" % (tablename, columnname))
        
    def show_columns(self, tablename):
        #Function used to show all columns in a given table
        mycursor = self.mydb.cursor(buffered=True)
        mycursor.execute("SHOW columns FROM %s" % (tablename))
        print(mycursor.fetchall())
        
    def main(self):
        """
        PREREQUISITES:
        Download MySQL Installer from https://dev.mysql.com/downloads/installer/
        Install any required files shown on your local computer
        Once installed you will be requested to create a database name, user and password. Save these credentials
        Update self.mydb variables with your database name and credentials
        
        If you need to change a table name, use the following function:
        #Amend given table name
        #self.change_table_name("old_name", "new_name")
        INDIVIDUAL STEPS:
        Below are the numbered steps used to setup the database and create the correct table names and column names
        Uncomment each line of code and run one-by-one. e.g.
        THIS COMMENT DESCRIBES WHAT THE CODE BELOW DOES                    --> #1. Display database python..
        UNCOMMENT THIS CODE BY DELETING THE '#' AT THE BEGINNING TO RUN IT --> #self.display_database()
        Once you have run each line/lines of code individually and not received any errors, the database has been
        setup as required and can now be used to take and store metadata and classification data generated by running
        the main.py function
        """
        #1. Display database python is connected to. This is defined in constructor as self.mydb where you entered your database credentials
        #self.display_database()
        #2. Define the table names and column names to be applied to all tables
        #tablenames = ['internal', 'legitimate', 'phishing', 'spam']
        #columnnames = ['ip_addresses', 'external_ips', 'urls', 'resolved_domains', 'body_text', 'body_language',
        #'body_sentiment', 'virus_total_reputation', 'cisco_talos_reputation', 'pydnsbl_reputation', 'classification', 'sender']
        #3. Create tables based on the table names defined in tablenames list
        #for t in range(0, len(tablenames)):
            #self.create_table(tablenames[t])
        #4. Create columns for each individual table based on column names defined in columnnames list
        #for t in range(0, len(tablenames)):
            #for c in range(0, len(columnnames)):
                #self.add_column(str(tablenames[t]), str(columnnames[c]))
        #5. Display current database tables
        #self.display_database_tables()
        #6. Create and add primary keys column and values to each table
        #for t in range(0, len(tablenames)):
            #self.add_primary_key(tablenames[t])
        #7. Display all columns within each table to check for any inconsistencies
        #for t in range(0, len(tablenames)):
            #self.show_columns(tablenames[t])
          
          
          
          
if __name__ == "__main__":
    sqld = sql_database()
    sqld.main()
